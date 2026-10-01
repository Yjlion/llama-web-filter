package models_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"0.0.0.0:8080", "0.0.0.0", 8080},
		{"127.0.0.1:53", "127.0.0.1", 53},
		{"[::1]:8080", "::1", 8080},
		{"::1:8080", "::1", 8080},
		{"example.com:443", "example.com", 443},
	}
	for _, c := range cases {
		host, port := models.SplitHostPort(c.in)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("SplitHostPort(%q) = (%q, %d), want (%q, %d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

func TestParseListen(t *testing.T) {
	cases := []struct {
		in       string
		wantMode string
		wantHost string
		wantPort int
	}{
		{"0.0.0.0:8080", "regular", "0.0.0.0", 8080},
		{"regular@0.0.0.0:8080", "regular", "0.0.0.0", 8080},
		{"socks5@0.0.0.0:1080", "socks5", "0.0.0.0", 1080},
		{"dns@0.0.0.0:53", "dns", "0.0.0.0", 53},
		{"tun", "tun", "", 0},
		{"local", "local", "", 0},
		{"wireguard@0.0.0.0:51820", "wireguard", "0.0.0.0", 51820},
		{"transparent@0.0.0.0:8080", "transparent", "0.0.0.0", 8080},
		{"socks4@0.0.0.0:1080", "socks4", "0.0.0.0", 1080},
		// TLS tokens resolve to their base mode; ParseListen drops the TLS flag.
		{"https@0.0.0.0:8443", "regular", "0.0.0.0", 8443},
		{"tls@0.0.0.0:1443", "socks5", "0.0.0.0", 1443},
		{"tls+socks4@0.0.0.0:1440", "socks4", "0.0.0.0", 1440},
	}
	for _, c := range cases {
		mode, host, port := models.ParseListen(c.in)
		if mode != c.wantMode || host != c.wantHost || port != c.wantPort {
			t.Errorf("ParseListen(%q) = (%q, %q, %d), want (%q, %q, %d)",
				c.in, mode, host, port, c.wantMode, c.wantHost, c.wantPort)
		}
	}
}

func TestParseListenSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantMode string
		wantTLS  bool
		wantHost string
		wantPort int
	}{
		{"0.0.0.0:8080", "regular", false, "0.0.0.0", 8080},
		{"regular@0.0.0.0:8080", "regular", false, "0.0.0.0", 8080},
		{"socks4@0.0.0.0:1080", "socks4", false, "0.0.0.0", 1080},
		{"socks5@0.0.0.0:1080", "socks5", false, "0.0.0.0", 1080},
		{"https@0.0.0.0:8443", "regular", true, "0.0.0.0", 8443},
		{"tls@0.0.0.0:1443", "socks5", true, "0.0.0.0", 1443},
		{"tls+regular@0.0.0.0:8443", "regular", true, "0.0.0.0", 8443},
		{"tls+socks5@0.0.0.0:1443", "socks5", true, "0.0.0.0", 1443},
		{"tls+socks4@0.0.0.0:1440", "socks4", true, "0.0.0.0", 1440},
		{"icap@0.0.0.0:1344", "icap", false, "0.0.0.0", 1344},
		// "icaps" is the scheme name ICAP clients use for the TLS variant,
		// so it is spelled that way here rather than as tls+icap.
		{"icaps@0.0.0.0:11344", "icap", true, "0.0.0.0", 11344},
		{"tls+icap@0.0.0.0:11344", "icap", true, "0.0.0.0", 11344},
		// Unknown TLS base falls through to a bare host:port parse.
		{"tls+bogus@0.0.0.0:9", "regular", false, "tls+bogus@0.0.0.0", 9},
	}
	for _, c := range cases {
		spec := models.ParseListenSpec(c.in)
		if spec.Mode != c.wantMode || spec.TLS != c.wantTLS || spec.Host != c.wantHost || spec.Port != c.wantPort {
			t.Errorf("ParseListenSpec(%q) = %+v, want mode=%q tls=%v host=%q port=%d",
				c.in, spec, c.wantMode, c.wantTLS, c.wantHost, c.wantPort)
		}
	}
}

func TestPrimaryRegularProxyPortSkipsTLS(t *testing.T) {
	s := models.NewGlobalSettings()
	// An https@ (TLS) listener must not be advertised as a plaintext PAC
	// PROXY target; the plaintext regular listener wins.
	s.ProxyListen = []string{"https@0.0.0.0:8443", "regular@0.0.0.0:8080"}
	if got := s.PrimaryRegularProxyPort(); got != 8080 {
		t.Errorf("PrimaryRegularProxyPort() = %d, want 8080 (TLS listener skipped)", got)
	}
}

func TestGlobalSettingsPrimaryProxyPortSkipsUnsupportedModes(t *testing.T) {
	s := models.NewGlobalSettings()
	s.ProxyListen = []string{"wireguard@0.0.0.0:51820", "socks5@0.0.0.0:1080"}
	if got := s.PrimaryProxyPort(); got != 1080 {
		t.Errorf("PrimaryProxyPort() = %d, want 1080 (first regular/socks5 entry)", got)
	}
}

func TestGlobalSettingsPrimaryRegularProxyPort(t *testing.T) {
	cases := []struct {
		name   string
		listen []string
		want   int
	}{
		{"regular first (bare form)", []string{"0.0.0.0:8080", "socks5@127.0.0.1:1080"}, 8080},
		{"socks5 only falls back", []string{"socks5@127.0.0.1:1080"}, 8080},
		{"regular after socks5 wins over fallback", []string{"socks5@127.0.0.1:1080", "regular@127.0.0.1:9090"}, 9090},
		{"empty falls back", nil, 8080},
	}
	for _, c := range cases {
		s := models.NewGlobalSettings()
		s.ProxyListen = c.listen
		if got := s.PrimaryRegularProxyPort(); got != c.want {
			t.Errorf("%s: PrimaryRegularProxyPort() = %d, want %d", c.name, got, c.want)
		}
	}
}
