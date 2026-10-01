package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// TestHTTPSProxyListener drives an https@ listener: the client establishes a
// TLS session to the proxy endpoint itself, then speaks the ordinary HTTP
// forward-proxy protocol (CONNECT) inside it. The proxy presents a leaf minted
// by the runtime CA for the address the client connected to (no SNI is sent
// for an IP-literal proxy), which the client trusts because it trusts the CA.
func TestHTTPSProxyListener(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello via https proxy")
	}))
	defer origin.Close()

	proxyAddr, rt := startModeEngine(t, "https@127.0.0.1:0", origin, nil, nil)

	// Trust the engine CA for BOTH TLS legs: the proxy endpoint's own leaf
	// and the MITM'd origin leaf are both signed by it.
	pool := x509.NewCertPool()
	pool.AddCert(rt.CA.Cert)

	proxyURL, _ := url.Parse("https://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through https proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello via https proxy" {
		t.Errorf("body = %q, want %q", body, "hello via https proxy")
	}
}

// TestTLSSocks5Listener drives a tls@ listener (SOCKS5-over-TLS): the client
// TLS-connects to the proxy, then performs the SOCKS5 handshake inside the TLS
// session.
func TestTLSSocks5Listener(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello via tls socks5")
	}))
	defer origin.Close()

	proxyAddr, rt := startModeEngine(t, "tls@127.0.0.1:0", nil, nil, nil)

	pool := x509.NewCertPool()
	pool.AddCert(rt.CA.Cert)

	// A TLS-terminating dialer: wrap the raw TCP connection to the proxy in
	// TLS, then hand it to the x/net SOCKS5 dialer as the underlying transport.
	tlsDialer := &tlsProxyDialer{addr: proxyAddr, cfg: &tls.Config{RootCAs: pool}}
	socks, err := xproxy.SOCKS5("tcp", proxyAddr, nil, tlsDialer)
	if err != nil {
		t.Fatalf("build socks dialer: %v", err)
	}
	transport := &http.Transport{Dial: socks.Dial} //nolint:staticcheck // test dialer
	client := &http.Client{Transport: transport}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET through tls socks5: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello via tls socks5" {
		t.Errorf("body = %q, want %q", body, "hello via tls socks5")
	}
}

// tlsProxyDialer is an xproxy.Dialer whose Dial always TLS-connects to a fixed
// proxy address, ignoring the requested addr - the x/net SOCKS5 dialer calls
// it to reach the proxy, and the SOCKS handshake then rides inside that TLS
// session.
type tlsProxyDialer struct {
	addr string
	cfg  *tls.Config
}

func (d *tlsProxyDialer) Dial(_, _ string) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", d.addr, d.cfg)
}
