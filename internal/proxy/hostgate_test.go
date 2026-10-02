package proxy_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/categories"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// gateRuntime is a Runtime with nothing but a category store: enough for
// HostFilterVerdict, which reads no other field.
func gateRuntime(t *testing.T) *state.Runtime {
	t.Helper()
	dir := t.TempDir()
	for name, domains := range map[string]string{
		"ads":  "ads.net\n",
		"kids": "kidsite.com\n",
	} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatalf("mkdir category %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "domains"), []byte(domains), 0o644); err != nil {
			t.Fatalf("write category %s: %v", name, err)
		}
	}
	return &state.Runtime{Categories: categories.NewStore(dir)}
}

func gatePolicy(urlFilter models.UrlFilterConfig, mitm *models.MitmConfig) *models.Policy {
	p := models.NewPolicy()
	p.Name = "gate"
	p.UrlFilter = urlFilter
	if mitm != nil {
		p.Mitm = *mitm
	}
	return &p
}

// TestHostFilterVerdict pins the host-only filtering applied to tunnels that
// are about to be blind-spliced. Those connections never reach an addon, so
// this function is the only filtering a MITM-excluded host ever gets.
func TestHostFilterVerdict(t *testing.T) {
	rt := gateRuntime(t)

	for _, tc := range []struct {
		name        string
		policy      *models.Policy
		host        string
		wantBlocked bool
	}{
		{
			name:   "no policy",
			policy: nil,
			host:   "ads.net",
		},
		{
			name:   "url filter disabled",
			policy: gatePolicy(models.UrlFilterConfig{Block: []string{"blocked.example"}}, nil),
			host:   "blocked.example",
		},
		{
			name:        "exact host in block list",
			policy:      gatePolicy(models.UrlFilterConfig{Enabled: true, Block: []string{"blocked.example"}}, nil),
			host:        "blocked.example",
			wantBlocked: true,
		},
		{
			name:        "wildcard block matches subdomain",
			policy:      gatePolicy(models.UrlFilterConfig{Enabled: true, Block: []string{"*.example.com"}}, nil),
			host:        "ads.example.com",
			wantBlocked: true,
		},
		{
			// A path pattern cannot be decided from a hostname; blocking the
			// whole host would block far more than the user asked for.
			name:   "path block pattern does not block the whole host",
			policy: gatePolicy(models.UrlFilterConfig{Enabled: true, Block: []string{"example.com/bad"}}, nil),
			host:   "example.com",
		},
		{
			name: "allow list wins over block list",
			policy: gatePolicy(models.UrlFilterConfig{
				Enabled: true,
				Allow:   []string{"example.com"},
				Block:   []string{"example.com"},
			}, nil),
			host: "example.com",
		},
		{
			// The mirror image of the block case: a path-scoped allow entry
			// must not grant the whole host a pass at connection level.
			name: "path allow pattern does not rescue a blocked host",
			policy: gatePolicy(models.UrlFilterConfig{
				Enabled: true,
				Allow:   []string{"example.com/ok"},
				Block:   []string{"example.com"},
			}, nil),
			host:        "example.com",
			wantBlocked: true,
		},
		{
			name: "blacklisted category",
			policy: gatePolicy(models.UrlFilterConfig{
				Enabled:    true,
				Mode:       models.UrlFilterModeBlacklist,
				Categories: []string{"ads"},
			}, nil),
			host:        "sub.ads.net",
			wantBlocked: true,
		},
		{
			name: "whitelist blocks an unlisted host",
			policy: gatePolicy(models.UrlFilterConfig{
				Enabled:    true,
				Mode:       models.UrlFilterModeWhitelist,
				Categories: []string{"kids"},
			}, nil),
			host:        "random.example",
			wantBlocked: true,
		},
		{
			name: "whitelist allows a listed host",
			policy: gatePolicy(models.UrlFilterConfig{
				Enabled:    true,
				Mode:       models.UrlFilterModeWhitelist,
				Categories: []string{"kids"},
			}, nil),
			host: "kidsite.com",
		},
		{
			// MitmControl marks include-mode non-listed sites passthrough and
			// UrlFilter skips them; the connection gate must agree.
			name: "mitm include mode leaves a non-listed host alone",
			policy: gatePolicy(
				models.UrlFilterConfig{Enabled: true, Block: []string{"blocked.example"}},
				&models.MitmConfig{Mode: models.MitmModeInclude, Sites: []string{"other.example"}},
			),
			host: "blocked.example",
		},
		{
			name: "mitm include mode still filters a listed host",
			policy: gatePolicy(
				models.UrlFilterConfig{Enabled: true, Block: []string{"blocked.example"}},
				&models.MitmConfig{Mode: models.MitmModeInclude, Sites: []string{"blocked.example"}},
			),
			host:        "blocked.example",
			wantBlocked: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := proxy.HostFilterVerdict(rt, tc.policy, tc.host)
			if got.Blocked != tc.wantBlocked {
				t.Fatalf("HostFilterVerdict(%q).Blocked = %v, want %v (reason %q)", tc.host, got.Blocked, tc.wantBlocked, got.Reason)
			}
			if !got.Blocked {
				return
			}
			if got.Component != "url_filter" {
				t.Errorf("component = %q, want url_filter", got.Component)
			}
			if got.Reason == "" {
				t.Error("expected a non-empty block reason")
			}
		})
	}
}

// writeGatePolicy writes p as the only policy file and reloads the snapshot
// synchronously (the fsnotify watcher isn't started in these tests).
func writeGatePolicy(t *testing.T, rt *state.Runtime, p models.Policy) {
	t.Helper()
	dir := rt.Settings().PoliciesDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir policies dir: %v", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gate.json"), data, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	rt.ReloadPolicies()
}

// connectResponse performs a raw CONNECT against the proxy and returns the
// status line's code plus the body, without ever speaking TLS - a refused
// tunnel answers with an ordinary HTTP error response.
func connectResponse(t *testing.T, proxyAddr, target string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		// A successful CONNECT hands the socket to the tunnel; its "body" is
		// the tunnel itself and reading it would block until the deadline.
		return resp.StatusCode, ""
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// socks5ConnectReply performs a no-auth SOCKS5 CONNECT for host:port and
// returns the reply code, so a policy refusal (0x02) can be told apart from a
// dial failure (0x01/0x05).
func socks5ConnectReply(t *testing.T, socksAddr, host string, port int) byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply[1]
}

// blockedHostPolicy MITM-excludes host (so the tunnel would be blind-spliced)
// and blocks it in url_filter - the exact combination that used to make a host
// unfilterable for every client.
func blockedHostPolicy(host string) models.Policy {
	p := models.NewPolicy()
	p.Name = "gate"
	p.Mitm = models.MitmConfig{Mode: models.MitmModeExclude, Sites: []string{host}}
	p.UrlFilter = models.UrlFilterConfig{Enabled: true, Mode: models.UrlFilterModeBlacklist, Block: []string{host}}
	return p
}

func TestConnectRefusesBlockedSplicedHost(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should never be reached")
	}))
	defer origin.Close()

	proxyAddr, rt := startEngineWithRuntime(t, origin)
	originHost, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	writeGatePolicy(t, rt, blockedHostPolicy(originHost))

	status, body := connectResponse(t, proxyAddr, net.JoinHostPort(originHost, originPort))
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT status = %d, want 403 (body %q)", status, body)
	}
	if !strings.Contains(body, "URL blocked by policy") {
		t.Errorf("body = %q, want the block reason", body)
	}

	// The Store embeds the read-only Reader, so this is the engine's own
	// connection - not a second one competing with its single writer.
	rows := rt.Logs.Tail("blocks", 10)
	if len(rows) == 0 {
		t.Fatal("expected a blocks-table row for the refused tunnel")
	}
	if got := rows[0]["component"]; got != "url_filter" {
		t.Errorf("blocks row component = %v, want url_filter", got)
	}
	if got := rows[0]["domain"]; got != originHost {
		t.Errorf("blocks row domain = %v, want %s", got, originHost)
	}
}

func TestSocks5RefusesBlockedSplicedHost(t *testing.T) {
	socksAddr, rt := startSocksEngine(t, nil, nil, nil)
	writeGatePolicy(t, rt, blockedHostPolicy("blocked.example"))

	if got := socks5ConnectReply(t, socksAddr, "blocked.example", 443); got != 0x02 {
		t.Errorf("SOCKS5 reply = 0x%02x, want 0x02 (connection not allowed by ruleset)", got)
	}
}

// TestConnectAllowsUnblockedSplicedHost is the counterweight: the gate must
// not turn every MITM-excluded host into a refusal.
func TestConnectAllowsUnblockedSplicedHost(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from bypassed origin")
	}))
	defer origin.Close()

	proxyAddr, rt := startEngineWithRuntime(t, origin)
	originHost, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	p := blockedHostPolicy(originHost)
	p.UrlFilter.Block = []string{"someone.else.example"}
	writeGatePolicy(t, rt, p)

	status, body := connectResponse(t, proxyAddr, net.JoinHostPort(originHost, originPort))
	if status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200 (body %q)", status, body)
	}
}

// TestConnectRefusesDoTWhenDnsFilteringIsOn covers the TCP half of the DNS
// bypass: a DoT client would otherwise be MITM'd and then have its DNS wire
// bytes fed to http.ReadRequest.
func TestConnectRefusesDoTWhenDnsFilteringIsOn(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	proxyAddr, rt := startEngineWithRuntime(t, origin)
	seedDohPolicy(t, rt, "https://dns.example.invalid/dns-query")

	status, body := connectResponse(t, proxyAddr, "127.0.0.1:853")
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT :853 status = %d, want 403 (body %q)", status, body)
	}
	if !strings.Contains(body, "DNS-over-TLS") {
		t.Errorf("body = %q, want the DoT block reason", body)
	}
}

// TestConnectSplicesDoTWithoutDnsFiltering pins the other half of the port-853
// rule: with no DNS filtering there is nothing to bypass, so the connection is
// spliced rather than refused or MITM'd. Nothing listens on 853 here, so the
// splice fails to dial - a 503, which is exactly how it differs from the 403 a
// policy refusal produces.
func TestConnectSplicesDoTWithoutDnsFiltering(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	proxyAddr, _ := startEngineWithRuntime(t, origin)

	status, body := connectResponse(t, proxyAddr, "127.0.0.1:853")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT :853 status = %d, want 503 (body %q)", status, body)
	}
}

type gateCategorizer struct{ asked []state.CategoryLookup }

func (g *gateCategorizer) Categorize(_ context.Context, q state.CategoryLookup) state.CategoryAnswer {
	g.asked = append(g.asked, q)
	if q.Host == "bet.example" {
		return state.CategoryAnswer{Category: "gambling", Known: true}
	}
	return state.CategoryAnswer{TimedOut: true}
}

func TestHostFilterVerdictCategoryFilter(t *testing.T) {
	rt := gateRuntime(t)
	cat := &gateCategorizer{}
	rt.SetSiteCategorizer(cat)
	p := gatePolicy(models.NewUrlFilterConfig(), nil) // url_filter disabled
	p.CategoryFilter = models.NewCategoryFilterConfig()
	p.CategoryFilter.Enabled = true
	p.CategoryFilter.Categories = []string{"gambling"}

	if v := proxy.HostFilterVerdict(rt, p, "bet.example"); !v.Blocked || v.Component != "category_filter" {
		t.Fatalf("cached gambling tunnel = %+v", v)
	}
	if v := proxy.HostFilterVerdict(rt, p, "new.example"); v.Blocked {
		t.Fatalf("unknown tunnel blocked: %+v", v)
	}
	for _, q := range cat.asked {
		if !q.Enqueue || q.Budget != 0 {
			t.Fatalf("tunnel lookup must queue without waiting: %+v", q)
		}
	}
	// Allow-only mode is never enforced on tunnels.
	p.CategoryFilter.Mode = models.UrlFilterModeWhitelist
	if v := proxy.HostFilterVerdict(rt, p, "bet.example"); v.Blocked {
		t.Fatalf("whitelist tunnel blocked: %+v", v)
	}
}
