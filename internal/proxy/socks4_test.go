package proxy_test

import (
	"bufio"
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

	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

// startModeEngine boots an Engine serving a single proxy_listen entry (any
// mode) on an ephemeral port, with a real state.Runtime backed by a freshly
// generated CA. It mirrors startSocksEngine but lets the caller pick the
// listen scheme (socks4@, https@, tls@, ...). Returns the bound address.
func startModeEngine(t *testing.T, listen string, trustedOrigin *httptest.Server, extra map[string]any, buildPipeline func(*state.Runtime) *proxy.Pipeline) (addr string, rt *state.Runtime) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
		"proxy_listen": []string{listen},
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
	bound := listeners[0].Addr().String()

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
	return bound, rt
}

// socks4Connect performs a SOCKS4 (dstIP set, no domain) or SOCKS4a (dstIP
// 0.0.0.1 + domain) CONNECT handshake on a fresh connection to the proxy and
// returns the tunneled connection positioned right after the 8-byte reply. It
// fails the test if the reply code is not "granted".
func socks4Connect(t *testing.T, proxyAddr string, dstIP net.IP, domain string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks4 proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := []byte{0x04, 0x01}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if domain != "" {
		req = append(req, 0, 0, 0, 1) // SOCKS4a marker 0.0.0.1
	} else {
		req = append(req, dstIP.To4()...)
	}
	req = append(req, 0x00) // empty USERID + NUL
	if domain != "" {
		req = append(req, []byte(domain)...)
		req = append(req, 0x00)
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks4 request: %v", err)
	}

	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read socks4 reply: %v", err)
	}
	if reply[0] != 0x00 {
		t.Fatalf("socks4 reply version = 0x%02x, want 0x00", reply[0])
	}
	if reply[1] != 0x5A {
		t.Fatalf("socks4 reply code = 0x%02x, want 0x5A (granted)", reply[1])
	}
	return conn
}

// httpGetOverTunnel writes a minimal HTTP/1.1 GET for host over an already
// established tunnel conn and returns the response.
func httpGetOverTunnel(t *testing.T, conn net.Conn, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+host+"/hello", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request over tunnel: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response over tunnel: %v", err)
	}
	return resp
}

func TestSocks4PlainHTTPForwarding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello over socks4")
	}))
	defer origin.Close()
	host, portStr, _ := net.SplitHostPort(origin.Listener.Addr().String())
	port, _ := net.LookupPort("tcp", portStr)

	proxyAddr, _ := startModeEngine(t, "socks4@127.0.0.1:0", nil, nil, nil)
	conn := socks4Connect(t, proxyAddr, net.ParseIP(host), "", port)
	defer conn.Close()

	resp := httpGetOverTunnel(t, conn, origin.Listener.Addr().String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello over socks4" {
		t.Errorf("body = %q, want %q", body, "hello over socks4")
	}
}

func TestSocks4aDomainConnect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello over socks4a")
	}))
	defer origin.Close()
	_, portStr, _ := net.SplitHostPort(origin.Listener.Addr().String())
	port, _ := net.LookupPort("tcp", portStr)

	proxyAddr, _ := startModeEngine(t, "socks4@127.0.0.1:0", nil, nil, nil)
	// SOCKS4a: resolve "localhost" proxy-side rather than sending an IP.
	conn := socks4Connect(t, proxyAddr, nil, "localhost", port)
	defer conn.Close()

	resp := httpGetOverTunnel(t, conn, net.JoinHostPort("localhost", portStr))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello over socks4a" {
		t.Errorf("body = %q, want %q", body, "hello over socks4a")
	}
}

// TestSocks4RejectsBindCommand asserts BIND (CD=0x02) is rejected with 0x5B.
func TestSocks4RejectsBindCommand(t *testing.T) {
	proxyAddr, _ := startModeEngine(t, "socks4@127.0.0.1:0", nil, nil, nil)
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := []byte{0x04, 0x02} // VN=4, CD=BIND
	req = binary.BigEndian.AppendUint16(req, 80)
	req = append(req, 127, 0, 0, 1, 0x00)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x5B {
		t.Errorf("reply code = 0x%02x, want 0x5B (rejected)", reply[1])
	}
}

// TestSocks4RejectedWhenAuthRequired asserts a SOCKS4 client is refused when
// the proxy requires credentials (SOCKS4 has no password channel).
func TestSocks4RejectedWhenAuthRequired(t *testing.T) {
	hash, err := pwhash.Hash("s3cret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	extra := map[string]any{
		"proxy_auth_enabled":       true,
		"proxy_auth_username":      "alice",
		"proxy_auth_password_hash": hash,
	}
	buildPipeline := func(rt *state.Runtime) *proxy.Pipeline {
		return proxy.NewPipeline([]proxy.Addon{addons.NewProxyAuthGate(rt)})
	}
	proxyAddr, _ := startModeEngine(t, "socks4@127.0.0.1:0", nil, extra, buildPipeline)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := []byte{0x04, 0x01}
	req = binary.BigEndian.AppendUint16(req, 80)
	req = append(req, 127, 0, 0, 1, 0x00)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x5B {
		t.Errorf("reply code = 0x%02x, want 0x5B (rejected, no SOCKS4 auth channel)", reply[1])
	}
}
