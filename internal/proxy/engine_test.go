package proxy_test

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// writeExcludePolicy writes a policy that MITM-excludes host, then
// synchronously reloads the runtime's policy snapshot (rather than relying
// on the fsnotify watcher's debounce, which is not started by
// startEngineWithRuntime's tests).
func writeExcludePolicy(t *testing.T, rt *state.Runtime, host string) {
	t.Helper()
	p := models.NewPolicy()
	p.Name = "bypass"
	p.Mitm = models.MitmConfig{Mode: models.MitmModeExclude, Sites: []string{host}}
	// startEngineWithRuntime seeds settings.json with an absolute
	// policies_dir, so this is directly usable without resolving relative
	// to the settings file's location.
	dir := rt.Settings().PoliciesDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir policies dir: %v", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bypass.json"), data, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	rt.ReloadPolicies()
}

// startEngine boots an Engine on an ephemeral port and serves it in the
// background until the test ends, returning the proxy's dial address.
func startEngine(t *testing.T, listen []string) string {
	t.Helper()
	eng := &proxy.Engine{
		Settings:  models.GlobalSettings{ProxyListen: listen},
		Transport: proxy.NewTransport(),
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
	return addr
}

func TestPlainHTTPForwarding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		io.WriteString(w, "hello from origin")
	}))
	defer origin.Close()

	proxyAddr := startEngine(t, []string{"127.0.0.1:0"})
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "yes" {
		t.Errorf("X-Origin header = %q, want yes", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello from origin" {
		t.Errorf("body = %q, want %q", body, "hello from origin")
	}
}

// TestProxyDecodesGzipUpstream verifies the engine strips the client's
// Accept-Encoding and lets the stdlib Transport negotiate + transparently
// decode gzip, so content-inspecting addons (and ultimately the client)
// always see identity bodies even when the client advertised encodings the
// stdlib can't decode (br, zstd).
func TestProxyDecodesGzipUpstream(t *testing.T) {
	const plaintext = "hello decoded origin body"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ae := r.Header.Get("Accept-Encoding")
		if !strings.Contains(ae, "gzip") {
			t.Errorf("upstream Accept-Encoding = %q, want gzip negotiated by the proxy", ae)
		}
		if strings.Contains(ae, "br") || strings.Contains(ae, "zstd") {
			t.Errorf("upstream Accept-Encoding = %q, client's own encodings must not leak through", ae)
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		io.WriteString(gz, plaintext)
		gz.Close()
	}))
	defer origin.Close()

	proxyAddr := startEngine(t, []string{"127.0.0.1:0"})
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	// Setting Accept-Encoding explicitly disables the client Transport's own
	// transparent gzip, so the body below is the raw bytes off the wire.
	req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q, want empty (identity) after proxy-side decode", ce)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != plaintext {
		t.Errorf("body = %q, want %q (decoded)", body, plaintext)
	}
}

func TestConnectBlindSplice(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello over tls")
	}))
	defer origin.Close()

	proxyAddr := startEngine(t, []string{"127.0.0.1:0"})
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(origin.Certificate())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through CONNECT tunnel: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello over tls" {
		t.Errorf("body = %q, want %q", body, "hello over tls")
	}
}

// "dns" stands in for the modes models.ParseListenSpec recognizes but the
// engine does not serve. It used to be "transparent", which is served on Linux
// now that gateway mode implements it.
func TestListenSkipsUnsupportedModes(t *testing.T) {
	eng := &proxy.Engine{Settings: models.GlobalSettings{
		ProxyListen: []string{"dns@127.0.0.1:0", "regular@127.0.0.1:0"},
	}}
	listeners, err := eng.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	if len(listeners) != 1 {
		t.Fatalf("len(listeners) = %d, want 1 (the dns entry should be skipped)", len(listeners))
	}
}

// TestListenBindsSocks5 verifies socks5-mode entries are now served (bound)
// alongside regular ones, each tagged with its mode.
func TestListenBindsSocks5(t *testing.T) {
	eng := &proxy.Engine{Settings: models.GlobalSettings{
		ProxyListen: []string{"socks5@127.0.0.1:0", "regular@127.0.0.1:0"},
	}}
	listeners, err := eng.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	if len(listeners) != 2 {
		t.Fatalf("len(listeners) = %d, want 2 (socks5 + regular both bound)", len(listeners))
	}
	modes := map[string]bool{}
	for _, l := range listeners {
		modes[l.Mode] = true
	}
	if !modes["socks5"] || !modes["regular"] {
		t.Fatalf("bound modes = %v, want both socks5 and regular", modes)
	}
}

func TestListenErrorsWhenNoSupportedEntries(t *testing.T) {
	eng := &proxy.Engine{Settings: models.GlobalSettings{
		ProxyListen: []string{"dns@127.0.0.1:0", "tun"},
	}}
	if _, err := eng.Listen(); err == nil {
		t.Fatal("Listen: expected error when no supported entries are configured, got nil")
	}
}

// startEngineWithRuntime boots an Engine with a real state.Runtime (backed
// by a freshly generated CA in a temp dir) so CONNECT requests go through
// genuine MITM interception rather than the Runtime-nil blind-splice
// fallback. trustedOrigin's certificate is added to the Transport's
// RootCAs so the engine's own upstream fetch (which performs real TLS
// verification) succeeds against a local httptest.NewTLSServer.
func startEngineWithRuntime(t *testing.T, trustedOrigin *httptest.Server) (proxyAddr string, rt *state.Runtime) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
		"proxy_listen": []string{"127.0.0.1:0"},
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
	pool := x509.NewCertPool()
	pool.AddCert(trustedOrigin.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}

	eng := &proxy.Engine{Settings: *rt.Settings(), Runtime: rt, Transport: transport}
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

func TestMitmInterceptionIssuesOwnLeafCertificate(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from MITM'd origin")
	}))
	defer origin.Close()

	proxyAddr, rt := startEngineWithRuntime(t, origin)
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	// Trust the ENGINE's own CA (not the origin's cert) - if interception
	// is genuinely happening, the leaf served over the CONNECT tunnel is
	// signed by this CA, not by whatever issued the origin's real cert.
	clientPool := x509.NewCertPool()
	clientPool.AddCert(rt.CA.Cert)

	// VerifyPeerCertificate lets us capture the leaf actually presented, so
	// we can assert below that it was issued by our CA rather than merely
	// that the client trusted it.
	var seenLeaf *x509.Certificate
	tlsConfig := &tls.Config{RootCAs: clientPool}
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) > 0 {
			if cert, err := x509.ParseCertificate(rawCerts[0]); err == nil {
				seenLeaf = cert
			}
		}
		return nil
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through MITM tunnel: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello from MITM'd origin" {
		t.Errorf("body = %q, want %q", body, "hello from MITM'd origin")
	}

	if seenLeaf == nil {
		t.Fatal("expected to capture the presented leaf certificate")
	}
	if err := seenLeaf.CheckSignatureFrom(rt.CA.Cert); err != nil {
		t.Errorf("leaf certificate was not signed by the engine's own CA: %v", err)
	}
	originLeaf := origin.Certificate()
	if seenLeaf.SerialNumber.Cmp(originLeaf.SerialNumber) == 0 {
		t.Error("leaf certificate matches the origin's own cert - MITM interception did not happen")
	}
}

func TestMitmBypassStillBlindSplices(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from bypassed origin")
	}))
	defer origin.Close()

	proxyAddr, rt := startEngineWithRuntime(t, origin)
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	writeExcludePolicy(t, rt, originHost)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	certPool := x509.NewCertPool()
	certPool.AddCert(origin.Certificate())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through bypassed tunnel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello from bypassed origin" {
		t.Errorf("body = %q, want %q", body, "hello from bypassed origin")
	}
}

// Gateway mode's front-end is a transparent listener, so the engine has to
// actually bind one now - it was parsed and skipped for the whole life of the
// port before this. Linux only: SO_ORIGINAL_DST is a netfilter facility, and
// binding elsewhere would accept connections that could never be routed.
func TestListenBindsTransparentOnLinuxOnly(t *testing.T) {
	eng := &proxy.Engine{Settings: models.GlobalSettings{
		ProxyListen: []string{"transparent@127.0.0.1:0", "regular@127.0.0.1:0"},
	}}
	listeners, err := eng.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	var transparent int
	for _, l := range listeners {
		if l.Mode == "transparent" {
			transparent++
		}
	}
	want := 0
	if runtime.GOOS == "linux" {
		want = 1
	}
	if transparent != want {
		t.Errorf("bound %d transparent listeners on %s, want %d", transparent, runtime.GOOS, want)
	}
}
