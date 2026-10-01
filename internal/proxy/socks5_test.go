package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

// startSocksEngine boots an Engine serving a single SOCKS5 listener on an
// ephemeral port with a real state.Runtime (backed by a freshly generated CA
// in a temp dir), so SOCKS connections go through genuine MITM interception.
// extra merges into the seeded settings.json (e.g. to enable proxy auth);
// buildPipeline, if non-nil, builds the addon pipeline from the runtime (used
// to wire the ProxyAuthGate for auth tests). trustedOrigin's certificate, when
// non-nil, is trusted by the engine's upstream Transport.
func startSocksEngine(t *testing.T, trustedOrigin *httptest.Server, extra map[string]any, buildPipeline func(*state.Runtime) *proxy.Pipeline) (socksAddr string, rt *state.Runtime) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
		"proxy_listen": []string{"socks5@127.0.0.1:0"},
	}
	for k, v := range extra {
		seed[k] = v
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

	rt, err = state.New(settingsPath)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	t.Cleanup(func() { rt.Logs.Close() })

	transport := proxy.NewTransport()
	if trustedOrigin != nil {
		pool := x509.NewCertPool()
		pool.AddCert(trustedOrigin.Certificate())
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	eng := &proxy.Engine{Settings: *rt.Settings(), Runtime: rt, Transport: transport}
	if buildPipeline != nil {
		eng.Pipeline = buildPipeline(rt)
	}
	listeners, err := eng.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := listeners[0].Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
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

// socksHTTPClient builds an http.Client that tunnels through the SOCKS5 proxy
// at socksAddr, optionally with RFC 1929 auth and a custom TLS config (to
// trust the engine's MITM CA).
func socksHTTPClient(t *testing.T, socksAddr string, auth *xproxy.Auth, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	dialer, err := xproxy.SOCKS5("tcp", socksAddr, auth, xproxy.Direct)
	if err != nil {
		t.Fatalf("build socks dialer: %v", err)
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	if cd, ok := dialer.(xproxy.ContextDialer); ok {
		transport.DialContext = cd.DialContext
	} else {
		transport.Dial = dialer.Dial //nolint:staticcheck // fallback when the dialer isn't a ContextDialer
	}
	return &http.Client{Transport: transport}
}

func TestSocks5PlainHTTPForwarding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		io.WriteString(w, "hello from origin over socks")
	}))
	defer origin.Close()

	socksAddr, _ := startSocksEngine(t, nil, nil, nil)
	client := socksHTTPClient(t, socksAddr, nil, nil)

	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("GET through SOCKS5: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "yes" {
		t.Errorf("X-Origin = %q, want yes", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from origin over socks" {
		t.Errorf("body = %q", body)
	}
}

func TestSocks5MitmInterception(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from MITM'd origin over socks")
	}))
	defer origin.Close()

	socksAddr, rt := startSocksEngine(t, origin, nil, nil)

	// Trust the engine's own CA - if interception is happening, the leaf
	// presented over the SOCKS tunnel is signed by this CA.
	clientPool := x509.NewCertPool()
	clientPool.AddCert(rt.CA.Cert)
	var seenLeaf *x509.Certificate
	tlsCfg := &tls.Config{RootCAs: clientPool}
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) > 0 {
			if cert, err := x509.ParseCertificate(rawCerts[0]); err == nil {
				seenLeaf = cert
			}
		}
		return nil
	}
	client := socksHTTPClient(t, socksAddr, nil, tlsCfg)

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through SOCKS5 MITM tunnel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from MITM'd origin over socks" {
		t.Errorf("body = %q", body)
	}
	if seenLeaf == nil {
		t.Fatal("expected to capture the presented leaf certificate")
	}
	if err := seenLeaf.CheckSignatureFrom(rt.CA.Cert); err != nil {
		t.Errorf("leaf not signed by the engine's CA: %v", err)
	}
	if seenLeaf.SerialNumber.Cmp(origin.Certificate().SerialNumber) == 0 {
		t.Error("leaf matches the origin's own cert - MITM did not happen")
	}
}

func TestSocks5MitmBypassBlindSplices(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from bypassed origin over socks")
	}))
	defer origin.Close()

	socksAddr, rt := startSocksEngine(t, origin, nil, nil)
	originHost, _, _ := net.SplitHostPort(origin.Listener.Addr().String())
	writeExcludePolicy(t, rt, originHost)

	// Blind-splice means no MITM: the client sees the origin's own cert, so
	// trust that (not the engine CA).
	certPool := x509.NewCertPool()
	certPool.AddCert(origin.Certificate())
	client := socksHTTPClient(t, socksAddr, nil, &tls.Config{RootCAs: certPool})

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through bypassed SOCKS tunnel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from bypassed origin over socks" {
		t.Errorf("body = %q", body)
	}
}

func TestSocks5AuthRequired(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "authed body")
	}))
	defer origin.Close()

	hash, err := pwhash.Hash("s3cret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	extra := map[string]any{
		"proxy_auth_enabled":       true,
		"proxy_auth_username":      "alice",
		"proxy_auth_password_hash": hash,
	}
	buildPipeline := func(rt *state.Runtime) *proxy.Pipeline {
		return proxy.NewPipeline([]proxy.Addon{addons.NewProxyAuthGate(rt)})
	}
	socksAddr, _ := startSocksEngine(t, nil, extra, buildPipeline)

	// Wrong password: the SOCKS handshake auth is rejected, so the dial fails.
	badClient := socksHTTPClient(t, socksAddr, &xproxy.Auth{User: "alice", Password: "wrong"}, nil)
	if _, err := badClient.Get(origin.URL); err == nil {
		t.Fatal("expected failure with bad SOCKS5 credentials, got success")
	}

	// Correct password: handshake authorizes, and tunneled requests aren't
	// re-challenged (a 407 body would prove otherwise).
	goodClient := socksHTTPClient(t, socksAddr, &xproxy.Auth{User: "alice", Password: "s3cret"}, nil)
	resp, err := goodClient.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET with good SOCKS5 credentials: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "authed body" {
		t.Errorf("body = %q, want %q (inner request must not be re-challenged)", body, "authed body")
	}
}

// TestSocks5RejectsBindCommand drives the raw handshake to assert that an
// unsupported command (BIND) gets reply code 0x07. UDP ASSOCIATE is now
// supported (see the UDP-relay tests in socks5_udp_test.go); BIND is not.
func TestSocks5RejectsBindCommand(t *testing.T) {
	socksAddr, _ := startSocksEngine(t, nil, nil, nil)

	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: VER=5, NMETHODS=1, METHOD=no-auth.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		t.Fatalf("method selection = %v, want [5 0]", sel)
	}

	// Request: VER=5, CMD=BIND (0x02), RSV=0, ATYP=IPv4, 0.0.0.0:0.
	req := []byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0}
	req = binary.BigEndian.AppendUint16(req, 0)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x07 {
		t.Errorf("reply code = 0x%02x, want 0x07 (command not supported)", reply[1])
	}
}
