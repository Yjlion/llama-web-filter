package addons

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// DohFilter intercepts DNS-over-HTTPS (RFC 8484 wireformat,
// application/dns-message) queries and blocks a domain when the
// configured resolver signals it's filtered. Ported from
// proxy/addons/doh_filter.py.
//
// A domain is blocked when the resolver returns NXDOMAIN, an Extended DNS
// Error (RFC 8914) info-code of Blocked(15)/Censored(16)/Filtered(17), or
// sinkholes it to a known sinkhole/block-page IP - the conventions
// filtering resolvers (NextDNS, Cloudflare, CleanBrowsing, AdGuard) use.
type DohFilter struct{}

func (DohFilter) Name() string { return "doh_filter" }

func (DohFilter) HandleRequest(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough {
		return
	}
	policy := fc.Policy
	if policy == nil || !policy.Doh.Enabled {
		return
	}
	host := fc.Request.URL.Hostname()
	if !dohShouldFilter(host, policy.Doh) {
		return
	}
	if queryDoh(host, policy.Doh.Server) {
		fc.Block(fmt.Sprintf("Domain blocked by DNS policy (%s)", policy.Doh.Server), "doh")
	}
}

func dohShouldFilter(host string, cfg models.DohConfig) bool {
	if len(cfg.IncludeOnly) > 0 {
		return proxy.DomainInList(host, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !proxy.DomainInList(host, cfg.Exclude)
	}
	return true
}

// dohHTTPClient never routes through a configured system proxy (which
// could be this proxy itself) - queries must go out directly. Mirrors
// httpx.AsyncClient(trust_env=False).
var dohHTTPClient = &http.Client{
	Timeout: 4 * time.Second,
	// The shared dialer also carries the TUN-capture egress mark, so a DoH
	// lookup is not itself captured and fed back into the engine.
	Transport: &http.Transport{Proxy: nil, DialContext: proxy.DialUpstreamContext},
}

// blockAddrStrings are sinkhole and provider block-page IPs, in the order
// filtering resolvers use them. Ported from doh_filter.py's
// _BLOCK_ADDR_STRINGS.
var blockAddrStrings = []string{
	"0.0.0.0", "::", "127.0.0.1", // sinkholes
	"94.140.14.35", "94.140.14.36", // AdGuard block page (IPv4)
	"2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff", // AdGuard block page (IPv6)
}

var blockAddrs = func() map[string]bool {
	m := make(map[string]bool, len(blockAddrStrings))
	for _, s := range blockAddrStrings {
		if ip := net.ParseIP(s); ip != nil {
			m[ip.String()] = true
		}
	}
	return m
}()

// edeBlockCodes are RFC 8914 Extended DNS Error info-codes meaning
// "blocked": Blocked(15), Censored(16), Filtered(17).
var edeBlockCodes = map[uint16]bool{15: true, 16: true, 17: true}

const (
	dohFailTTL = 30 * time.Second  // cache a failed lookup briefly (fail-open, retry soon)
	dohMaxTTL  = 600 * time.Second // cap how long a verdict is cached
)

type dohCacheKey struct{ host, server string }
type dohCacheEntry struct {
	blocked bool
	expires time.Time
}

var (
	dohCacheMu sync.Mutex
	dohCache   = make(map[dohCacheKey]dohCacheEntry)
)

// queryDoh returns whether host is blocked according to server, using a
// short-lived cache so a busy proxy doesn't repeat the same lookup for
// every request to the same host. Ported from doh_filter.py's
// _query_doh/_classify.
func queryDoh(host, server string) bool {
	key := dohCacheKey{host, server}
	now := time.Now()

	dohCacheMu.Lock()
	if entry, ok := dohCache[key]; ok && now.Before(entry.expires) {
		dohCacheMu.Unlock()
		return entry.blocked
	}
	dohCacheMu.Unlock()

	type result struct {
		msg *dns.Msg
		err error
	}
	resultsCh := make(chan result, 2)
	go func() { m, err := resolveDoh(host, server, dns.TypeA); resultsCh <- result{m, err} }()
	go func() { m, err := resolveDoh(host, server, dns.TypeAAAA); resultsCh <- result{m, err} }()

	var messages []*dns.Msg
	var lastErr error
	for i := 0; i < 2; i++ {
		r := <-resultsCh
		if r.err != nil {
			lastErr = r.err
			continue
		}
		messages = append(messages, r.msg)
	}

	if len(messages) == 0 {
		slog.Warn("doh_filter: lookup failed", "host", host, "server", server, "err", lastErr)
		dohCacheMu.Lock()
		dohCache[key] = dohCacheEntry{blocked: false, expires: now.Add(dohFailTTL)}
		dohCacheMu.Unlock()
		return false
	}

	blocked, detail, ttl := classifyDoh(messages)
	if blocked {
		slog.Info("doh_filter: blocked", "host", host, "server", server, "detail", detail)
	}
	if ttl > dohMaxTTL {
		ttl = dohMaxTTL
	}
	dohCacheMu.Lock()
	dohCache[key] = dohCacheEntry{blocked: blocked, expires: now.Add(ttl)}
	dohCacheMu.Unlock()
	return blocked
}

func classifyDoh(messages []*dns.Msg) (blocked bool, detail string, ttl time.Duration) {
	ttl = 300 * time.Second
	for _, msg := range messages {
		if msg.Rcode == dns.RcodeNameError {
			return true, "NXDOMAIN", 300 * time.Second
		}
		if detail := edeBlockDetail(msg); detail != "" {
			return true, detail, 300 * time.Second
		}
		for _, rr := range msg.Answer {
			addr := rrAddress(rr)
			if addr != "" && blockAddrs[addr] {
				rrTTL := time.Duration(rr.Header().Ttl) * time.Second
				if rrTTL < time.Second {
					rrTTL = time.Second
				}
				return true, "block-ip " + addr, rrTTL
			}
			if rr.Header().Ttl > 0 {
				rrTTL := time.Duration(rr.Header().Ttl) * time.Second
				if rrTTL < time.Second {
					rrTTL = time.Second
				}
				if rrTTL < ttl {
					ttl = rrTTL
				}
			}
		}
	}
	return false, "", ttl
}

func rrAddress(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	default:
		return ""
	}
}

func edeBlockDetail(msg *dns.Msg) string {
	opt := msg.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		ede, ok := o.(*dns.EDNS0_EDE)
		if !ok || !edeBlockCodes[ede.InfoCode] {
			continue
		}
		if ede.ExtraText != "" {
			return fmt.Sprintf("EDE %d: %s", ede.InfoCode, ede.ExtraText)
		}
		return fmt.Sprintf("EDE %d", ede.InfoCode)
	}
	return ""
}

// DohRecord is one resource record in a diagnostic DoH query result.
type DohRecord struct {
	Type string `json:"type"`
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// DohToolResult is the outcome of a diagnostic DoH lookup, matching the
// shape the management UI's DoH tool expects (GET/POST /api/tools/doh).
type DohToolResult struct {
	Server  string      `json:"server"`
	Domain  string      `json:"domain"`
	Records []DohRecord `json:"records"`
	Blocked bool        `json:"blocked"`
	Detail  string      `json:"detail"`
	Rcode   string      `json:"rcode"`
}

// QueryDohDetailed runs A + AAAA DoH lookups for domain against server and
// reports every resource record plus the block verdict - the diagnostic
// counterpart to queryDoh (which only returns blocked/not and caches).
// Mirrors the Python management API's /api/tools/doh handler: it never
// errors, encoding an all-queries-failed outcome as an empty record set with
// a SERVFAIL rcode and an explanatory detail.
func QueryDohDetailed(domain, server string) DohToolResult {
	res := DohToolResult{Server: server, Domain: domain, Records: []DohRecord{}}

	type result struct {
		msg *dns.Msg
		err error
	}
	ch := make(chan result, 2)
	go func() { m, err := resolveDoh(domain, server, dns.TypeA); ch <- result{m, err} }()
	go func() { m, err := resolveDoh(domain, server, dns.TypeAAAA); ch <- result{m, err} }()

	var messages []*dns.Msg
	var lastErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
			continue
		}
		messages = append(messages, r.msg)
	}

	if len(messages) == 0 {
		res.Rcode = "SERVFAIL"
		if lastErr != nil {
			res.Detail = "query failed: " + lastErr.Error()
		} else {
			res.Detail = "query failed"
		}
		return res
	}

	blocked, detail, _ := classifyDoh(messages)
	res.Blocked = blocked
	res.Detail = detail
	res.Rcode = dns.RcodeToString[messages[0].Rcode]

	for _, msg := range messages {
		for _, rr := range msg.Answer {
			hdr := rr.Header()
			data := rrAddress(rr)
			if data == "" {
				// Non-address record: strip the leading header tokens so we
				// report just the rdata (mirrors dnspython's rd.to_text()).
				data = rdataText(rr)
			}
			res.Records = append(res.Records, DohRecord{
				Type: dns.TypeToString[hdr.Rrtype],
				Name: hdr.Name,
				TTL:  hdr.Ttl,
				Data: data,
			})
		}
	}
	return res
}

// rdataText returns just the rdata portion of a resource record's text form
// (miekg's rr.String() prepends "name ttl class type").
func rdataText(rr dns.RR) string {
	full := rr.String()
	hdr := rr.Header().String()
	return strings.TrimPrefix(full, hdr)
}

// resolveDoh sends one RFC 8484 wireformat query over HTTPS POST.
func resolveDoh(host, server string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.SetEdns0(1232, false)

	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, server, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh request: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}
	return respMsg, nil
}
