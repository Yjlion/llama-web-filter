package app_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/app"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// newMgmtServer builds a Server rooted in a temp dir on a free port, with
// absolute directory paths (the documented defaults are relative and would
// otherwise resolve against the test process's working directory).
func newMgmtServer(t *testing.T, mutate func(*models.GlobalSettings)) (*mgmtapi.Server, int) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")

	port := freePort(t)
	cfg := models.NewGlobalSettings()
	cfg.MgmtHost = "127.0.0.1"
	cfg.MgmtPort = port
	cfg.CertDir = filepath.Join(dir, "certs")
	cfg.PoliciesDir = filepath.Join(dir, "policies")
	cfg.LogsDir = filepath.Join(dir, "logs")
	cfg.CategoriesDir = filepath.Join(dir, "categories")
	if mutate != nil {
		mutate(&cfg)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	srv, err := mgmtapi.NewServer(settingsPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Logs.Close() })
	return srv, port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// serve runs ServeMgmt in the background and waits for the port to accept.
func serve(t *testing.T, srv *mgmtapi.Server, port int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- app.ServeMgmt(ctx, srv) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("ServeMgmt returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("ServeMgmt did not return after context cancel")
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case err := <-errCh:
			t.Fatalf("ServeMgmt failed to start: %v", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("management server never accepted on %s", addr)
}

// caPool reads the generated CA off disk, which is exactly what a client
// (or the native GUI's mgmtclient) has to do to trust a CA-minted leaf.
func caPool(t *testing.T, certDir string) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("CA PEM contained no certificates")
	}
	return pool
}

func TestServeMgmtPlaintextByDefault(t *testing.T) {
	srv, port := newMgmtServer(t, nil)
	serve(t, srv, port)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/version", port))
	if err != nil {
		t.Fatalf("plain HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// With mgmt_tls on and no cert files, the server presents a leaf minted by
// the runtime CA - the same issuer TLS-wrapped proxy listeners use.
func TestServeMgmtTLSUsesCAMintedLeaf(t *testing.T) {
	var certDir string
	srv, port := newMgmtServer(t, func(c *models.GlobalSettings) {
		c.MgmtTLS = true
		certDir = c.CertDir
	})
	serve(t, srv, port)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool(t, certDir), MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/version", port))
	if err != nil {
		t.Fatalf("HTTPS request against CA-minted leaf: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("empty body over TLS")
	}
}

// An IP-literal client sends no SNI, so the leaf has to be issued for the
// address the connection landed on or verification fails. This is the rule
// certs.ServerTLSConfig shares with the proxy; it is easy to regress.
func TestServeMgmtTLSWorksWithoutSNI(t *testing.T) {
	var certDir string
	srv, port := newMgmtServer(t, func(c *models.GlobalSettings) {
		c.MgmtTLS = true
		certDir = c.CertDir
	})
	serve(t, srv, port)

	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		RootCAs:    caPool(t, certDir),
		ServerName: "", // no SNI, as a real IP-literal client sends
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("SNI-less TLS handshake: %v", err)
	}
	defer conn.Close()

	// The leaf must actually cover the IP the client connected to.
	leaf := conn.ConnectionState().PeerCertificates[0]
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("leaf does not cover 127.0.0.1: %v", err)
	}
}

// Plain HTTP must not still be served on the TLS port; otherwise "I turned
// on HTTPS" would be a false statement about the login POST.
func TestServeMgmtTLSRefusesPlaintext(t *testing.T) {
	srv, port := newMgmtServer(t, func(c *models.GlobalSettings) { c.MgmtTLS = true })
	serve(t, srv, port)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/version", port))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("plain HTTP got 200 from a TLS-only management server")
		}
	}
}

// ForcePlaintext is what the Android path sets; it must win over mgmt_tls.
func TestForcePlaintextOverridesMgmtTLS(t *testing.T) {
	srv, port := newMgmtServer(t, func(c *models.GlobalSettings) { c.MgmtTLS = true })
	srv.ForcePlaintext = true
	serve(t, srv, port)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/version", port))
	if err != nil {
		t.Fatalf("plain HTTP with ForcePlaintext: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (ForcePlaintext must override mgmt_tls)", resp.StatusCode)
	}
}

// An explicit cert/key pair is used instead of the CA, so an operator can
// front the UI with a publicly trusted certificate.
func TestServeMgmtTLSUsesCertFilesWhenSet(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := writeSelfSignedPair(t, dir)

	srv, port := newMgmtServer(t, func(c *models.GlobalSettings) {
		c.MgmtTLS = true
		c.MgmtCertFile = certPath
		c.MgmtKeyFile = keyPath
	})
	serve(t, srv, port)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/version", port))
	if err != nil {
		t.Fatalf("HTTPS with explicit cert files: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMgmtURLScheme(t *testing.T) {
	cfg := models.NewGlobalSettings()
	cfg.MgmtPort = 8000

	if got, want := app.MgmtURL(cfg, "127.0.0.1", false), "http://127.0.0.1:8000"; got != want {
		t.Errorf("plaintext MgmtURL = %q, want %q", got, want)
	}
	cfg.MgmtTLS = true
	if got, want := app.MgmtURL(cfg, "127.0.0.1", false), "https://127.0.0.1:8000"; got != want {
		t.Errorf("TLS MgmtURL = %q, want %q", got, want)
	}
	if got, want := app.MgmtURL(cfg, "127.0.0.1", true), "http://127.0.0.1:8000"; got != want {
		t.Errorf("forced-plaintext MgmtURL = %q, want %q", got, want)
	}
}
