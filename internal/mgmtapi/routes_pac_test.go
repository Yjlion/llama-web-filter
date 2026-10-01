package mgmtapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRenderPACQuotesProxyDirective(t *testing.T) {
	proxyHost := "proxy\"; alert(1);//\nnext\\host"
	proxyPort := 8080
	pac := renderPAC(proxyHost, proxyPort, nil, nil)

	var returnLine string
	for _, line := range strings.Split(pac, "\n") {
		if strings.Contains(line, "PROXY ") {
			returnLine = strings.TrimSpace(line)
			break
		}
	}
	if returnLine == "" {
		t.Fatalf("PAC output missing proxy return line:\n%s", pac)
	}

	const prefix = "return "
	const suffix = ";"
	if !strings.HasPrefix(returnLine, prefix) || !strings.HasSuffix(returnLine, suffix) {
		t.Fatalf("proxy return line is not a single return statement: %q", returnLine)
	}
	literal := strings.TrimSuffix(strings.TrimPrefix(returnLine, prefix), suffix)
	got, err := strconv.Unquote(literal)
	if err != nil {
		t.Fatalf("proxy return value is not a valid quoted string literal %q: %v", literal, err)
	}
	want := fmt.Sprintf("PROXY %s:%d", proxyHost, proxyPort)
	if got != want {
		t.Fatalf("proxy directive = %q, want %q", got, want)
	}

	for _, raw := range []string{
		`return "PROXY proxy"; alert(1);//`,
		"//\nnext",
	} {
		if strings.Contains(pac, raw) {
			t.Fatalf("PAC output contains raw injected JavaScript %q:\n%s", raw, pac)
		}
	}
}

// pacTestServer builds a Server whose settings carry the given proxy_listen
// entries (seeded with absolute temp dirs per the repo's relative-default
// gotcha).
func pacTestServer(t *testing.T, proxyListen []string) *Server {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
		"proxy_listen": proxyListen,
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
	s, err := NewServer(settingsPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.Logs.Close() })
	return s
}

// TestPACAdvertisesRegularProxyPort pins that the PROXY directive names an
// HTTP ("regular") listener: a socks5-only configuration (the Android
// default) must fall back to 8080 — the port EnsureLocalHTTPProxyListener
// injects — not advertise the SOCKS port as an HTTP proxy.
func TestPACAdvertisesRegularProxyPort(t *testing.T) {
	cases := []struct {
		name   string
		listen []string
		want   string
	}{
		{"socks5-only falls back to 8080", []string{"socks5@127.0.0.1:1080"}, "PROXY 127.0.0.1:8080"},
		{"custom regular port respected", []string{"socks5@127.0.0.1:1080", "regular@127.0.0.1:9090"}, "PROXY 127.0.0.1:9090"},
	}
	for _, c := range cases {
		s := pacTestServer(t, c.listen)
		req := httptest.NewRequest("GET", "http://127.0.0.1:8000/proxy.pac", nil)
		rec := httptest.NewRecorder()
		s.handlePAC(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: /proxy.pac status = %d, want 200", c.name, rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, c.want) {
			t.Errorf("%s: PAC missing %q:\n%s", c.name, c.want, body)
		}
	}
}
