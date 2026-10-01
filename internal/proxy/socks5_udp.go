package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// SOCKS5 UDP-relay tunables.
const (
	// udpAssociateIdleTimeout bounds how long a UDP association - and each
	// individual destination socket within it - stays open with no traffic
	// before being torn down.
	udpAssociateIdleTimeout = 60 * time.Second
	// dnsUpstreamTimeout caps a single upstream DNS resolution (plain or DoH).
	dnsUpstreamTimeout = 5 * time.Second
	// dnsPort is relayed through the policy-aware resolver rather than blindly
	// forwarded, so DoH filtering applies to TUN-captured lookups.
	dnsPort = 53
	// quicPort is dropped outright. QUIC (HTTP/3) is end-to-end encrypted with
	// no MITM seam, so forwarding UDP/443 would let a browser tunnel straight
	// past URL filtering, SafeSearch, YouTube rewriting and the classifiers.
	// Dropping it makes browsers fall back to TCP/TLS, which the engine can
	// inspect. Note this is deliberately unconditional and NOT gated on
	// url_filter.block_quic: that flag only strips the Alt-Svc header, so
	// gating on it would leave the bypass open for anyone who turned it off.
	quicPort = 443
	// dotPort carries DNS-over-TLS on TCP and DNS-over-QUIC on UDP. Both are
	// dropped/refused rather than filtered, for the same reason as QUIC: there
	// is no seam to inspect them through (a DoT/DoQ client validates against
	// the system trust store, not this proxy's CA), and refusing makes clients
	// fall back to a resolver the pipeline does filter. The TCP half is
	// enforced in handleTunnel; this constant is shared by both.
	dotPort = 853
	// maxSniffedDNSQuery bounds how large a datagram may be before the
	// looks-like-DNS sniff gives up. Stub-resolver queries are tiny; a large
	// datagram is some other protocol whose bytes happened to parse.
	maxSniffedDNSQuery = 4096
	// maxConcurrentDNS bounds in-flight resolutions per association so one slow
	// upstream can't stall the read loop or spawn unbounded goroutines. A
	// browser fires many parallel DNS queries, so this must be > 1.
	maxConcurrentDNS = 256
	// maxUDPSessions caps the per-destination sockets one association may hold
	// open at once; past the cap the least recently used is evicted. Generous
	// for real traffic, but bounds fd usage against a client that sprays
	// datagrams at many destinations.
	maxUDPSessions = 512
	// udpDatagramSize is the read buffer per relayed datagram, sized to the
	// largest a UDP payload can be so nothing is silently truncated.
	udpDatagramSize = 65535
)

var errShortUDPPacket = errors.New("socks5: short UDP relay packet")

// serveSocksUDPAssociate handles a SOCKS5 UDP ASSOCIATE request (RFC 1928).
// It binds a UDP relay socket, tells the client where to send datagrams, and
// then relays the datagrams the client encapsulates through it.
//
// This exists for the TUN paths (Android's VpnService and the desktop
// tun2socks process): tun2socks forwards every captured UDP flow to the SOCKS
// proxy via UDP ASSOCIATE. DNS is UDP, so without a relay a client behind the
// TUN can never resolve a hostname and no TCP CONNECT — and therefore no
// filtering — ever happens. Everything else the OS sends over UDP (NTP, game
// and VoIP traffic, WireGuard, mDNS, ...) needs to reach the network too, or
// the machine simply looks broken once the TUN is up.
//
// Some destinations are special:
//
//   - Port 53 - and any other port carrying what looks like a DNS query, since
//     a resolver on a nonstandard port is otherwise a free bypass - is resolved
//     through resolveDNS instead of being blindly forwarded, so the policy's
//     DoH filtering applies to TUN-captured lookups.
//   - Ports 443 (QUIC) and 853 (DNS-over-QUIC) are dropped. Neither has a MITM
//     seam, so relaying them would hand clients a way around the entire
//     pipeline.
//
// Everything else is forwarded verbatim: the engine can't inspect opaque UDP
// anyway, so passing it through costs no filtering coverage.
//
// The TCP control connection stays open for the association's lifetime; when
// the client closes it, or the relay goes idle, the relay is torn down (RFC
// 1928: "a UDP association terminates when the TCP connection ... terminates").
func (e *Engine) serveSocksUDPAssociate(conn net.Conn, clientIP string) {
	// Bind the relay on the same local address the control connection arrived
	// on. For the TUN case that is loopback; for a LAN client of a 0.0.0.0
	// listener it is the reachable interface address, which a hardcoded
	// 127.0.0.1 bind would not be.
	bindIP := net.IPv4(127, 0, 0, 1)
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok && local.IP != nil && !local.IP.IsUnspecified() {
		bindIP = local.IP
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		writeSocksReply(conn, repGeneralFailure)
		return
	}
	defer relay.Close()

	bound := relay.LocalAddr().(*net.UDPAddr)
	if err := writeSocksReplyUDP(conn, bound.IP, bound.Port); err != nil {
		return
	}

	// The client keeps the TCP control connection open for as long as it wants
	// the association; when it closes, tear down the relay to unblock the loop.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		relay.Close()
	}()

	a := &udpAssociation{
		engine:   e,
		relay:    relay,
		clientIP: clientIP,
		peerIP:   hostOnlyOf(conn.RemoteAddr().String()),
		sessions: make(map[string]*udpSession),
	}
	defer a.close()
	a.run()
}

// udpAssociation is one live UDP ASSOCIATE: the relay socket the client sends
// to, plus the per-destination sockets its datagrams are forwarded through.
//
// Each destination gets its own connected UDP socket so replies arrive on a
// stable source port, which is what any NAT-traversing or session-oriented UDP
// protocol expects. Sockets are reused across datagrams and expire on idle.
type udpAssociation struct {
	engine   *Engine
	relay    *net.UDPConn
	clientIP string // policy-lookup identity, from the control connection
	peerIP   string // the only source address datagrams are accepted from

	mu         sync.Mutex
	clientAddr *net.UDPAddr // learned from the first datagram; where replies go
	sessions   map[string]*udpSession
	closed     bool
	wg         sync.WaitGroup
}

// udpSession is one destination socket within an association.
type udpSession struct {
	conn *net.UDPConn
	// rawAddr is the SOCKS address header of the destination, echoed verbatim
	// on every reply so the client sees answers as coming from the address it
	// addressed.
	rawAddr  []byte
	lastUsed time.Time
}

// run reads SOCKS-encapsulated datagrams from the client until the relay is
// closed (control connection gone) or goes idle. DNS is resolved in its own
// goroutine (bounded by maxConcurrentDNS) so a slow upstream can't stall the
// loop; everything else is a non-blocking send onto a destination socket.
func (a *udpAssociation) run() {
	var dnsWG sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentDNS)
	defer dnsWG.Wait()

	// One buffer for the whole loop: anything handed to another goroutine is
	// copied out first.
	buf := make([]byte, udpDatagramSize)
	for {
		_ = a.relay.SetReadDeadline(time.Now().Add(udpAssociateIdleTimeout))
		n, clientAddr, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return // deadline exceeded or relay closed
		}
		if !a.acceptFrom(clientAddr) {
			continue
		}

		rawAddr, host, port, payload, err := decodeSocksUDPPacket(buf[:n])
		if err != nil {
			continue
		}

		switch udpVerdictFor(port, payload) {
		case udpDrop:
			slog.Debug("socks5: dropped datagram with no filtering seam", "dst", host, "port", port, "client", a.clientIP)
		case udpResolveDNS:
			rawAddr, payload := append([]byte(nil), rawAddr...), append([]byte(nil), payload...)
			sem <- struct{}{}
			dnsWG.Add(1)
			go func() {
				defer dnsWG.Done()
				defer func() { <-sem }()

				resp := a.engine.resolveDNS(payload, host, port, a.clientIP)
				if resp == nil {
					return
				}
				// net.UDPConn writes are safe for concurrent use; loopback
				// sends don't block, so no per-write deadline is needed.
				_, _ = a.relay.WriteToUDP(encodeSocksUDPPacket(rawAddr, resp), clientAddr)
			}()
		case udpForward:
			a.forward(rawAddr, host, port, payload)
		}
	}
}

// udpVerdict is what the relay does with a datagram, decided by its
// destination port.
type udpVerdict int

const (
	// udpForward relays the datagram verbatim over a per-destination socket.
	udpForward udpVerdict = iota
	// udpResolveDNS answers it through the policy-aware resolver instead.
	udpResolveDNS
	// udpDrop discards it.
	udpDrop
)

// udpVerdictFor classifies a datagram by destination port, falling back to the
// payload for ports that carry no fixed protocol. Forwarding is the default
// because the engine cannot inspect opaque UDP anyway, so dropping it buys no
// filtering coverage while breaking every UDP protocol on a machine whose
// traffic a TUN is capturing.
//
// The payload sniff exists because port 53 is a convention, not a rule: a
// client configured to resolve through a resolver on some other port would
// otherwise skip the policy's DNS filtering entirely. Misclassifying a
// non-DNS datagram costs little (it is still delivered to the address the
// client chose, just via resolveDNS's own socket), but looksLikeDNSQuery is
// strict anyway so ordinary UDP protocols are never rerouted.
func udpVerdictFor(dstPort int, payload []byte) udpVerdict {
	switch dstPort {
	case quicPort, dotPort:
		return udpDrop
	case dnsPort:
		return udpResolveDNS
	}
	if looksLikeDNSQuery(payload) {
		return udpResolveDNS
	}
	return udpForward
}

// looksLikeDNSQuery reports whether payload is a plausible stub-resolver DNS
// query: a well-formed header with QR/AA/TC/Z/RCODE clear, opcode QUERY,
// exactly one question, no answer or authority records, and a question that
// actually parses. miekg's Unpack alone is not enough - it tolerates trailing
// bytes and untrusted section counts - so the header is checked directly
// first.
func looksLikeDNSQuery(payload []byte) bool {
	const (
		headerLen = 12
		flagQR    = 0x8000 // response, not query
		flagAA    = 0x0400 // authoritative answer: never set in a query
		flagTC    = 0x0200 // truncated
		flagZ     = 0x0040 // reserved, must be zero
		maskRcode = 0x000F
	)
	// +5 is the smallest possible question: a root name plus qtype/qclass.
	if len(payload) < headerLen+5 || len(payload) > maxSniffedDNSQuery {
		return false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&(flagQR|flagAA|flagTC|flagZ|maskRcode) != 0 {
		return false
	}
	if (flags>>11)&0xF != 0 { // opcode must be QUERY
		return false
	}
	if binary.BigEndian.Uint16(payload[4:6]) != 1 { // exactly one question
		return false
	}
	if binary.BigEndian.Uint16(payload[6:8]) != 0 || binary.BigEndian.Uint16(payload[8:10]) != 0 {
		return false // a query carries no answer or authority records
	}
	if binary.BigEndian.Uint16(payload[10:12]) > 2 { // at most EDNS0 + TSIG
		return false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil || len(msg.Question) != 1 {
		return false
	}
	q := msg.Question[0]
	return q.Name != "" && (q.Qclass == dns.ClassINET || q.Qclass == dns.ClassANY)
}

// acceptFrom pins the association to the first source address it hears from and
// ignores datagrams from anywhere else. The relay port is otherwise an open
// forwarder for any local process that guesses it, and RFC 1928 expects
// datagrams only from the client that opened the association.
func (a *udpAssociation) acceptFrom(addr *net.UDPAddr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientAddr == nil {
		// Port is free to differ from the control connection's, but the host
		// must match: only the client that authenticated may use this relay.
		if a.peerIP != "" && addr.IP.String() != a.peerIP {
			return false
		}
		a.clientAddr = addr
		return true
	}
	return addr.IP.Equal(a.clientAddr.IP) && addr.Port == a.clientAddr.Port
}

// forward sends one payload to its destination over that destination's session
// socket, opening the socket on first use.
func (a *udpAssociation) forward(rawAddr []byte, host string, port int, payload []byte) {
	s := a.session(rawAddr, host, port)
	if s == nil {
		return
	}
	// Refresh the idle deadline the reader goroutine is blocked on, so an
	// actively used session doesn't expire mid-flow.
	_ = s.conn.SetReadDeadline(time.Now().Add(udpAssociateIdleTimeout))
	_, _ = s.conn.Write(payload)
}

// session returns the destination socket for host:port, creating it if needed.
// Returns nil when the destination can't be dialled (unresolvable name, no
// route), in which case the datagram is dropped - UDP is lossy by definition,
// so the client's own retry is the recovery path.
func (a *udpAssociation) session(rawAddr []byte, host string, port int) *udpSession {
	key := net.JoinHostPort(host, strconv.Itoa(port))

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	if s, ok := a.sessions[key]; ok {
		s.lastUsed = time.Now()
		a.mu.Unlock()
		return s
	}
	a.mu.Unlock()

	// Dial outside the lock: name resolution can block.
	conn, err := DialUpstream("udp", key)
	if err != nil {
		slog.Debug("socks5: UDP destination unreachable", "dst", key, "err", err)
		return nil
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil
	}

	s := &udpSession{
		conn:     udpConn,
		rawAddr:  append([]byte(nil), rawAddr...),
		lastUsed: time.Now(),
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		udpConn.Close()
		return nil
	}
	// Another datagram for the same destination may have raced us here; keep
	// the winner so both sides agree on one socket per destination.
	if existing, ok := a.sessions[key]; ok {
		existing.lastUsed = time.Now()
		a.mu.Unlock()
		udpConn.Close()
		return existing
	}
	evicted := a.evictLockedIfFull()
	a.sessions[key] = s
	a.wg.Add(1)
	a.mu.Unlock()

	if evicted != nil {
		evicted.conn.Close()
	}
	go a.readSession(key, s)
	return s
}

// evictLockedIfFull drops the least recently used session when the map is at
// capacity, returning it so the caller can close it outside the lock. Evicting
// the oldest rather than refusing the newest keeps a flood of one-shot
// destinations from locking out ongoing flows' successors.
//
// Caller must hold a.mu.
func (a *udpAssociation) evictLockedIfFull() *udpSession {
	if len(a.sessions) < maxUDPSessions {
		return nil
	}
	var oldestKey string
	var oldest *udpSession
	for k, s := range a.sessions {
		if oldest == nil || s.lastUsed.Before(oldest.lastUsed) {
			oldestKey, oldest = k, s
		}
	}
	delete(a.sessions, oldestKey)
	return oldest
}

// readSession pumps replies from one destination back to the client, wrapped in
// the SOCKS UDP header. It exits when the socket is closed or goes idle for
// udpAssociateIdleTimeout with no traffic in either direction.
func (a *udpAssociation) readSession(key string, s *udpSession) {
	defer a.wg.Done()
	defer a.dropSession(key, s)

	buf := make([]byte, udpDatagramSize)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(udpAssociateIdleTimeout))
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}

		a.mu.Lock()
		clientAddr := a.clientAddr
		a.mu.Unlock()
		if clientAddr == nil {
			return
		}
		if _, err := a.relay.WriteToUDP(encodeSocksUDPPacket(s.rawAddr, buf[:n]), clientAddr); err != nil {
			return
		}
	}
}

// dropSession removes a finished session, but only if it is still the one
// registered under key - an eviction may already have replaced it.
func (a *udpAssociation) dropSession(key string, s *udpSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessions[key] == s {
		delete(a.sessions, key)
	}
}

// close tears down every destination socket and waits for the reader
// goroutines to finish, so an association leaves nothing behind.
func (a *udpAssociation) close() {
	a.mu.Lock()
	a.closed = true
	sessions := make([]*udpSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		sessions = append(sessions, s)
	}
	a.sessions = nil
	a.mu.Unlock()

	for _, s := range sessions {
		s.conn.Close()
	}
	a.wg.Wait()
}

// resolveDNS answers one DNS query. When the applicable policy enables DoH
// filtering and the queried name is in scope, it resolves through the policy's
// DoH server (a filtering resolver, which returns NXDOMAIN/sinkhole for blocked
// names); otherwise it forwards the query verbatim to the resolver the client
// addressed (the VpnService-configured DNS server on the mobile path). Returns
// nil when resolution fails, so the relay simply drops the datagram and the
// client retries — fail-open, matching doh_filter's behaviour.
func (e *Engine) resolveDNS(query []byte, dstHost string, dstPort int, clientIP string) []byte {
	var policy *models.Policy
	if e.Runtime != nil {
		policy = e.Runtime.GetPolicy(clientIP)
	}

	name := dnsQuestionName(query)
	if policy != nil && policy.Doh.Enabled && dnsShouldFilter(name, policy.Doh) {
		if resp := forwardDoh(query, policy.Doh.Server); resp != nil {
			if dnsResponseBlocked(resp) {
				e.logDNSBlock(name, policy, clientIP)
			}
			return resp
		}
		// DoH resolver unreachable: fall back to plain DNS rather than break
		// browsing entirely. Fail-open matches doh_filter's behaviour on
		// lookup failure (filtering is best-effort during a resolver outage).
		slog.Warn("doh_filter: DoH resolve failed, falling back to plain DNS", "host", name, "server", policy.Doh.Server)
	}

	upstream := net.JoinHostPort(dstHost, strconv.Itoa(dstPort))
	return forwardPlainDNS(query, upstream)
}

// dnsShouldFilter mirrors doh_filter.go's dohShouldFilter: include_only wins,
// then exclude, else everything is in scope. An unparseable name is out of
// scope (resolved plainly) rather than force-filtered.
func dnsShouldFilter(host string, cfg models.DohConfig) bool {
	if host == "" {
		return false
	}
	if len(cfg.IncludeOnly) > 0 {
		return DomainInList(host, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !DomainInList(host, cfg.Exclude)
	}
	return true
}

func (e *Engine) logDNSBlock(name string, policy *models.Policy, clientIP string) {
	metrics.Blocks.Inc("doh")
	if e.Runtime == nil || e.Runtime.Logs == nil {
		return
	}
	slog.Info("doh_filter: blocked", "host", name, "server", policy.Doh.Server, "via", "dns")
	_ = e.Runtime.Logs.LogBlock(logstore.BlockEntry{
		TS:        time.Now().Unix(),
		Domain:    name,
		URL:       "dns://" + name,
		Reason:    "Domain blocked by DNS policy (" + policy.Doh.Server + ")",
		Component: "doh",
		Policy:    policy.Name,
		ClientIP:  clientIP,
	})
}

// proxyDohClient POSTs DNS wireformat queries to a DoH endpoint. Like
// doh_filter's client it never routes through a configured system proxy (which
// could be this proxy itself) — resolutions must go out directly.
var proxyDohClient = &http.Client{
	Timeout:   dnsUpstreamTimeout,
	Transport: &http.Transport{Proxy: nil, DialContext: DialUpstreamContext},
}

// forwardDoh relays a raw DNS query wire to an RFC 8484 DoH server and returns
// the raw response wire (which preserves the client's transaction ID). Returns
// nil on any failure.
func forwardDoh(query []byte, server string) []byte {
	req, err := http.NewRequest(http.MethodPost, server, bytes.NewReader(query))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := proxyDohClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	return body
}

// forwardPlainDNS relays a raw DNS query to a plain UDP resolver and returns
// the raw response. Returns nil on any failure.
func forwardPlainDNS(query []byte, server string) []byte {
	conn, err := DialUpstreamTimeout("udp", server, dnsUpstreamTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

// dnsQuestionName returns the lowercased, dot-trimmed first question name of a
// DNS query wire, or "" if it can't be parsed.
func dnsQuestionName(query []byte) string {
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil || len(msg.Question) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
}

// dnsResponseBlocked reports whether a DNS response wire signals a filtered
// domain: NXDOMAIN, an RFC 8914 Extended DNS Error block info-code, or a
// sinkhole/block-page answer IP — the conventions filtering resolvers use.
// Mirrors doh_filter.go's classifyDoh (block-detection half).
func dnsResponseBlocked(resp []byte) bool {
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		return false
	}
	if msg.Rcode == dns.RcodeNameError {
		return true
	}
	if opt := msg.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok && edeBlockCodes[ede.InfoCode] {
				return true
			}
		}
	}
	for _, rr := range msg.Answer {
		var addr string
		switch v := rr.(type) {
		case *dns.A:
			addr = v.A.String()
		case *dns.AAAA:
			addr = v.AAAA.String()
		default:
			continue
		}
		if ip := net.ParseIP(addr); ip != nil && dnsBlockAddrs[ip.String()] {
			return true
		}
	}
	return false
}

// edeBlockCodes are RFC 8914 Extended DNS Error info-codes meaning "blocked":
// Blocked(15), Censored(16), Filtered(17). Mirrors doh_filter.go.
var edeBlockCodes = map[uint16]bool{15: true, 16: true, 17: true}

// dnsBlockAddrs are sinkhole and provider block-page IPs. Mirrors
// doh_filter.go's blockAddrStrings.
var dnsBlockAddrs = func() map[string]bool {
	strs := []string{
		"0.0.0.0", "::", "127.0.0.1", // sinkholes
		"94.140.14.35", "94.140.14.36", // AdGuard block page (IPv4)
		"2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff", // AdGuard block page (IPv6)
	}
	m := make(map[string]bool, len(strs))
	for _, s := range strs {
		if ip := net.ParseIP(s); ip != nil {
			m[ip.String()] = true
		}
	}
	return m
}()

// decodeSocksUDPPacket parses a SOCKS5 UDP request datagram (RFC 1928 §7):
// RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA. It returns the raw address
// header (ATYP+ADDR+PORT, reused verbatim when wrapping the reply), the parsed
// destination host/port, and the payload. Fragmented datagrams (FRAG != 0) are
// rejected — this relay doesn't reassemble.
func decodeSocksUDPPacket(pkt []byte) (rawAddr []byte, host string, port int, payload []byte, err error) {
	if len(pkt) < 5 {
		return nil, "", 0, nil, errShortUDPPacket
	}
	if pkt[0] != 0 || pkt[1] != 0 {
		return nil, "", 0, nil, errors.New("socks5: nonzero UDP RSV")
	}
	if pkt[2] != 0 {
		return nil, "", 0, nil, errors.New("socks5: fragmented UDP unsupported")
	}

	atyp := pkt[3]
	var addrLen int
	switch atyp {
	case atypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case atypIPv6:
		addrLen = 1 + net.IPv6len + 2
	case atypDomain:
		dlen := int(pkt[4])
		addrLen = 1 + 1 + dlen + 2
	default:
		return nil, "", 0, nil, errUnsupportedAddrType
	}
	if len(pkt) < 3+addrLen {
		return nil, "", 0, nil, errShortUDPPacket
	}

	rawAddr = pkt[3 : 3+addrLen]
	payload = pkt[3+addrLen:]

	portBytes := rawAddr[addrLen-2:]
	port = int(binary.BigEndian.Uint16(portBytes))
	switch atyp {
	case atypIPv4:
		host = net.IP(rawAddr[1 : 1+net.IPv4len]).String()
	case atypIPv6:
		host = net.IP(rawAddr[1 : 1+net.IPv6len]).String()
	case atypDomain:
		host = string(rawAddr[2 : 2+int(rawAddr[1])])
	}
	return rawAddr, host, port, payload, nil
}

// encodeSocksUDPPacket wraps a DNS response payload in a SOCKS5 UDP reply
// datagram, echoing the request's address header so the client sees the reply
// as coming from the address it queried.
func encodeSocksUDPPacket(rawAddr, payload []byte) []byte {
	out := make([]byte, 0, 3+len(rawAddr)+len(payload))
	out = append(out, 0x00, 0x00, 0x00) // RSV, RSV, FRAG
	out = append(out, rawAddr...)
	out = append(out, payload...)
	return out
}

// writeSocksReplyUDP writes a SOCKS5 success reply whose BND.ADDR/BND.PORT is
// the UDP relay the client should send datagrams to.
func writeSocksReplyUDP(w io.Writer, ip net.IP, port int) error {
	reply := []byte{socksVersion, repSucceeded, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		reply = append(reply, atypIPv4)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, atypIPv6)
		reply = append(reply, ip.To16()...)
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(port))
	_, err := w.Write(reply)
	return err
}
