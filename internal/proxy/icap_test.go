package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// startICAPEngine boots an Engine serving only an ICAP listener, with the
// real pipeline order, and returns the address an ICAP client should connect
// to.
//
// There is deliberately no origin server and no Transport here: in ICAP mode
// this process never fetches anything. The proxy on the other end does that,
// which is exactly the property these tests are checking.
func startICAPEngine(t *testing.T, policies ...models.Policy) (icapAddr string, rt *state.Runtime) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
		"proxy_listen": []string{"icap@127.0.0.1:0"},
	}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed settings: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatalf("write seed settings: %v", err)
	}

	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	for i, p := range policies {
		body, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			t.Fatalf("marshal policy: %v", err)
		}
		name := fmt.Sprintf("%02d-%s.json", i, p.Name)
		if err := os.WriteFile(filepath.Join(policyDir, name), body, 0o644); err != nil {
			t.Fatalf("write policy: %v", err)
		}
	}

	rt, err = state.New(settingsPath)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	t.Cleanup(func() { rt.Logs.Close() })
	rt.ReloadPolicies()

	eng := &proxy.Engine{
		Settings:  *rt.Settings(),
		Runtime:   rt,
		Transport: proxy.NewTransport(),
		Pipeline: proxy.NewPipeline([]proxy.Addon{
			addons.ManagementAccess{},
			addons.NewProxyAuthGate(rt),
			addons.PolicyRouter{},
			addons.MitmControl{},
			addons.UrlFilter{},
			addons.QuicBlocker{},
			addons.SafeSearch{},
			addons.RequestLogger{},
		}),
	}
	listeners, err := eng.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := listeners[0].Addr().String()

	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- eng.Serve(ctx, listeners) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("engine did not shut down within 5s of cancel")
		}
	})
	return addr, rt
}

// icapExchange sends one raw ICAP transaction and returns everything the
// server wrote back. Half-closing after the request is what makes the server
// finish the transaction and then hang up, so the read ends without a timer.
func icapExchange(t *testing.T, addr, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial icap: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write icap request: %v", err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read icap response: %v", err)
	}
	return string(out)
}

// reqmod renders a REQMOD transaction for an absolute-form request.
func reqmod(clientIP, requestHead string) string {
	head := "REQMOD icap://127.0.0.1/reqmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Allow: 204\r\n"
	if clientIP != "" {
		head += "X-Client-IP: " + clientIP + "\r\n"
	}
	return head +
		"Encapsulated: req-hdr=0, null-body=" + strconv.Itoa(len(requestHead)) + "\r\n\r\n" +
		requestHead
}

// respmod renders a RESPMOD transaction carrying both the request that
// produced the response and the response itself.
func respmod(clientIP, requestHead, responseHead, body string) string {
	head := "RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Allow: 204\r\n"
	if clientIP != "" {
		head += "X-Client-IP: " + clientIP + "\r\n"
	}
	encap := "req-hdr=0, res-hdr=" + strconv.Itoa(len(requestHead)) +
		", res-body=" + strconv.Itoa(len(requestHead)+len(responseHead))
	chunked := "0\r\n\r\n"
	if body != "" {
		chunked = fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	}
	return head + "Encapsulated: " + encap + "\r\n\r\n" + requestHead + responseHead + chunked
}

// permissivePolicy builds a catch-all policy with no URL rules. Several
// response-phase behaviours (Alt-Svc stripping among them) are policy
// settings, so "no policy at all" is not the same as "a policy that allows
// everything" - a test that wants the latter must say so.
func permissivePolicy(name string) models.Policy {
	p := models.NewPolicy()
	p.Name = name
	return p
}

// blockingPolicy builds a policy that URL-blocks host for the given clients.
func blockingPolicy(name, host string, sourceIPs ...string) models.Policy {
	p := models.NewPolicy()
	p.Name = name
	p.SourceIPs = append([]string{}, sourceIPs...)
	p.UrlFilter.Enabled = true
	p.UrlFilter.Block = []string{host}
	return p
}

func TestICAPOptionsAdvertisesBothVectoringPoints(t *testing.T) {
	addr, _ := startICAPEngine(t)

	for _, tc := range []struct{ uri, wantMethod string }{
		{"icap://127.0.0.1/reqmod", "REQMOD"},
		{"icap://127.0.0.1/respmod", "RESPMOD"},
	} {
		got := icapExchange(t, addr, "OPTIONS "+tc.uri+" ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n")
		if !strings.Contains(got, "Methods: "+tc.wantMethod) {
			t.Errorf("OPTIONS %s did not advertise %s:\n%s", tc.uri, tc.wantMethod, got)
		}
		for _, want := range []string{"ICAP/1.0 200 OK", "ISTag: \"wf-", "Allow: 204", "Preview: 4096"} {
			if !strings.Contains(got, want) {
				t.Errorf("OPTIONS %s missing %q:\n%s", tc.uri, want, got)
			}
		}
	}
}

// The ISTag is what an ICAP client caches adapted objects against. If it did
// not move when policies change, a newly blocked site would keep being served
// from the proxy's cache.
func TestICAPISTagChangesWithPolicyReload(t *testing.T) {
	addr, rt := startICAPEngine(t)
	options := "OPTIONS icap://127.0.0.1/respmod ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"

	before := istagOf(t, icapExchange(t, addr, options))
	rt.ReloadPolicies()
	after := istagOf(t, icapExchange(t, addr, options))

	if before == after {
		t.Errorf("ISTag %q unchanged across a policy reload", before)
	}
}

func istagOf(t *testing.T, response string) string {
	t.Helper()
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(line, "ISTag:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "ISTag:"))
		}
	}
	t.Fatalf("no ISTag in response:\n%s", response)
	return ""
}

func TestICAPReqmodAllowsUnfilteredRequest(t *testing.T) {
	addr, _ := startICAPEngine(t)
	got := icapExchange(t, addr, reqmod("192.168.1.50",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	if !strings.HasPrefix(got, "ICAP/1.0 204") {
		t.Errorf("want 204 for an unfiltered request, got:\n%s", got)
	}
}

func TestICAPReqmodBlockedURLReturnsBlockPage(t *testing.T) {
	addr, rt := startICAPEngine(t, blockingPolicy("default", "blocked.example"))
	got := icapExchange(t, addr, reqmod("192.168.1.50",
		"GET http://blocked.example/x HTTP/1.1\r\nHost: blocked.example\r\n\r\n"))

	if !strings.HasPrefix(got, "ICAP/1.0 200 OK") {
		t.Fatalf("want a 200 carrying the block page, got:\n%s", got)
	}
	// The encapsulated message must be a *response*: that is what tells the
	// proxy to answer the client instead of contacting the origin.
	if !strings.Contains(got, "Encapsulated: res-hdr=0") {
		t.Errorf("block did not encapsulate a response:\n%s", got)
	}
	if !strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Errorf("block page should be HTTP 200 with a block body, got:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "<html") {
		t.Errorf("block page body missing:\n%s", got)
	}
	assertBlockLogged(t, rt, "blocked.example")
}

// Per-client policy is the whole point of X-Client-IP: the TCP peer is the
// proxy, so without the header every user in the building would share one
// policy.
func TestICAPClientIPSelectsPolicy(t *testing.T) {
	addr, _ := startICAPEngine(t,
		blockingPolicy("kids", "blocked.example", "192.168.1.50"),
		blockingPolicy("adults", "nothing.example", "192.168.1.51"),
	)
	request := "GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n"

	if got := icapExchange(t, addr, reqmod("192.168.1.50", request)); !strings.HasPrefix(got, "ICAP/1.0 200") {
		t.Errorf("client matched by the blocking policy was not blocked:\n%s", got)
	}
	if got := icapExchange(t, addr, reqmod("192.168.1.51", request)); !strings.HasPrefix(got, "ICAP/1.0 204") {
		t.Errorf("client on the permissive policy was blocked anyway:\n%s", got)
	}
}

// A CONNECT reaching REQMOD is the proxy asking whether to open a tunnel.
// Refusing it is the only filtering available for traffic the proxy goes on
// to splice rather than decrypt.
func TestICAPReqmodConnectRefusesBlockedHost(t *testing.T) {
	addr, rt := startICAPEngine(t, blockingPolicy("default", "blocked.example"))
	got := icapExchange(t, addr, reqmod("192.168.1.50",
		"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n"))

	if !strings.Contains(got, "HTTP/1.1 403") {
		t.Errorf("blocked CONNECT should be refused with 403, got:\n%s", got)
	}
	// The refusal still carries the styled block page: browsers render the
	// body of a failed CONNECT, so a blocked HTTPS host looks the same to the
	// user as a blocked HTTP one.
	if !strings.Contains(strings.ToLower(got), "<html") {
		t.Errorf("refused CONNECT carried no block page:\n%s", got)
	}
	assertBlockLogged(t, rt, "blocked.example")
}

func TestICAPReqmodConnectAllowsPermittedHost(t *testing.T) {
	addr, _ := startICAPEngine(t, blockingPolicy("default", "blocked.example"))
	got := icapExchange(t, addr, reqmod("192.168.1.50",
		"CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n"))

	if !strings.HasPrefix(got, "ICAP/1.0 204") {
		t.Errorf("permitted CONNECT should pass, got:\n%s", got)
	}
}

// Bodies must reach the addons decoded. The service asks for gzip rather than
// stripping Accept-Encoding entirely so the origin leg stays compressed,
// which is the same trade the engine's own MITM path makes.
func TestICAPReqmodNormalizesAcceptEncoding(t *testing.T) {
	addr, _ := startICAPEngine(t)
	got := icapExchange(t, addr, reqmod("192.168.1.50",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: br, zstd, gzip\r\n\r\n"))

	if !strings.HasPrefix(got, "ICAP/1.0 200 OK") {
		t.Fatalf("want a 200 carrying the rewritten request, got:\n%s", got)
	}
	if !strings.Contains(got, "Encapsulated: req-hdr=0") {
		t.Errorf("rewritten request not encapsulated as a request:\n%s", got)
	}
	if !strings.Contains(got, "Accept-Encoding: gzip\r\n") || strings.Contains(got, "zstd") {
		t.Errorf("Accept-Encoding not normalised to gzip:\n%s", got)
	}
}

func TestICAPRespmodLeavesCleanResponseAlone(t *testing.T) {
	addr, _ := startICAPEngine(t, permissivePolicy("default"))
	got := icapExchange(t, addr, respmod("192.168.1.50",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n",
		"hello"))

	if !strings.HasPrefix(got, "ICAP/1.0 204") {
		t.Errorf("an unmodified response should be 204, got:\n%s", got)
	}
}

// Alt-Svc is how an origin tells a browser to switch to HTTP/3 and leave the
// proxy behind, so stripping it is a response-phase modification that must
// come back as a 200.
func TestICAPRespmodStripsAltSvc(t *testing.T) {
	addr, _ := startICAPEngine(t, permissivePolicy("default"))
	got := icapExchange(t, addr, respmod("192.168.1.50",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAlt-Svc: h3=\":443\"\r\nContent-Length: 5\r\n\r\n",
		"hello"))

	if !strings.HasPrefix(got, "ICAP/1.0 200 OK") {
		t.Fatalf("stripping Alt-Svc is a modification, want 200, got:\n%s", got)
	}
	if strings.Contains(got, "Alt-Svc") {
		t.Errorf("Alt-Svc survived:\n%s", got)
	}
	if !strings.Contains(got, "5\r\nhello\r\n0\r\n\r\n") {
		t.Errorf("body not handed back intact:\n%s", got)
	}
}

// A body larger than the cap is waved through rather than buffered - but the
// request is still logged, because "we did not inspect this" is exactly the
// thing an operator needs to be able to see.
func TestICAPRespmodOversizeBodyPassesButLogs(t *testing.T) {
	addr, rt := startICAPEngine(t, permissivePolicy("default"))
	huge := strconv.Itoa(64 << 20)
	got := icapExchange(t, addr, respmod("192.168.1.50",
		"GET http://example.com/big.bin HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "+huge+"\r\n\r\n",
		"partial"))

	if !strings.HasPrefix(got, "ICAP/1.0 204") {
		t.Errorf("oversize body should pass unfiltered, got:\n%s", got)
	}
	if n := countRequestRows(t, rt, "example.com"); n == 0 {
		t.Error("oversize response produced no requests-log row")
	}
}

// Proxy auth belongs to the proxy in ICAP mode: the ICAP peer is Squid, and
// one ICAP connection carries many users, so a 407 here could never be
// answered.
func TestICAPIgnoresProxyAuthSetting(t *testing.T) {
	addr, rt := startICAPEngine(t)
	cfg := *rt.Settings()
	cfg.ProxyAuthEnabled = true
	cfg.ProxyAuthUsername = "u"
	cfg.ProxyAuthPasswordHash = "pbkdf2_sha256$1$abc$def"
	rt.SetSettings(cfg)

	got := icapExchange(t, addr, reqmod("192.168.1.50",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	if strings.Contains(got, "407") {
		t.Errorf("ICAP flow was challenged for proxy credentials:\n%s", got)
	}
	if !strings.HasPrefix(got, "ICAP/1.0 204") {
		t.Errorf("want 204, got:\n%s", got)
	}
}

// assertBlockLogged checks the blocks table through the read-only Reader -
// never a second Configure(), which would open a competing writer against the
// engine's single-writer database.
func assertBlockLogged(t *testing.T, rt *state.Runtime, domain string) {
	t.Helper()
	rows := logstore.NewReader(rt.Settings().DBPath()).Tail("blocks", 50)
	for _, r := range rows {
		if fmt.Sprint(r["domain"]) == domain {
			return
		}
	}
	t.Errorf("no blocks-log row for %q (got %d rows)", domain, len(rows))
}

func countRequestRows(t *testing.T, rt *state.Runtime, host string) int {
	t.Helper()
	n := 0
	for _, r := range logstore.NewReader(rt.Settings().DBPath()).Tail("requests", 50) {
		if fmt.Sprint(r["host"]) == host {
			n++
		}
	}
	return n
}

// respmodPreview renders a RESPMOD that previews only the first previewLen
// bytes of body, leaving the rest to be sent after a 100 Continue.
func respmodPreview(clientIP, requestHead, responseHead, body string, previewLen int) (head, rest string) {
	icapHead := "RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Allow: 204\r\n" +
		"Preview: " + strconv.Itoa(previewLen) + "\r\n"
	if clientIP != "" {
		icapHead += "X-Client-IP: " + clientIP + "\r\n"
	}
	encap := "req-hdr=0, res-hdr=" + strconv.Itoa(len(requestHead)) +
		", res-body=" + strconv.Itoa(len(requestHead)+len(responseHead))
	preview := body[:previewLen]
	head = icapHead + "Encapsulated: " + encap + "\r\n\r\n" + requestHead + responseHead +
		fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(preview), preview)
	tail := body[previewLen:]
	rest = fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(tail), tail)
	return head, rest
}

// A previewed transaction reaches the handler twice, and the second pass must
// not mistake the parked upstream response for a block verdict. It did once:
// every previewed response came back as a 200 with an empty body, which a real
// Squid turned into zero-byte downloads.
func TestICAPRespmodPreviewThenContinueReturnsFullBody(t *testing.T) {
	addr, _ := startICAPEngine(t, permissivePolicy("default"))
	body := strings.Repeat("A", 40)
	head, rest := respmodPreview("192.168.1.50",
		"GET http://example.com/big.bin HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 40\r\n\r\n",
		body, 8)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatalf("write preview: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read interim: %v", err)
	}
	if !strings.HasPrefix(status, "ICAP/1.0 100 Continue") {
		t.Fatalf("want 100 Continue for a partial preview, got %q", status)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read interim terminator: %v", err)
	}
	if _, err := io.WriteString(conn, rest); err != nil {
		t.Fatalf("write remainder: %v", err)
	}
	final, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	// Nothing about this response needs changing, so the only correct answer
	// is 204 - which also means the proxy keeps serving its own copy of the
	// body rather than one this service would have to reproduce.
	if !strings.HasPrefix(final, "ICAP/1.0 204") {
		out, _ := io.ReadAll(br)
		t.Errorf("want 204 after continue, got %q followed by:\n%s", final, out)
	}
}
