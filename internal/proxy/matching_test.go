package proxy_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/proxy"
)

func TestHostMatches(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", true},
		{"notexample.com", "*.example.com", false},
		// The "*." fast path does a literal suffix comparison on whatever
		// follows it - it does not glob-interpret the rest of the pattern,
		// matching proxy/matching.py's host_matches exactly.
		{"foo.example.com", "*.example.*", false},
		{"foo.example.com", "*.example.com", true},
		{"", "", false},
	}
	for _, c := range cases {
		if got := proxy.HostMatches(c.host, c.pattern); got != c.want {
			t.Errorf("HostMatches(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestUrlMatchesPathPattern(t *testing.T) {
	host := "example.com"
	url := "https://example.com/path/file.html"

	if !proxy.UrlMatches(host, url, "example.com/path/*") {
		t.Error("expected glob path match")
	}
	if !proxy.UrlMatches(host, url, "https://example.com/path/*") {
		t.Error("expected scheme-included glob path match")
	}
	if !proxy.UrlMatches(host, url, "example.com/path/file.html") {
		t.Error("expected scheme-less prefix match")
	}
	if proxy.UrlMatches(host, url, "example.com/other/*") {
		t.Error("did not expect a match for an unrelated path")
	}
}

func TestUrlMatchesHostPattern(t *testing.T) {
	if !proxy.UrlMatches("example.com", "https://example.com/", "*.example.com") {
		t.Error("expected host pattern to match bare domain")
	}
}

func TestUrlInList(t *testing.T) {
	patterns := []string{"", "  ", "other.com", "*.example.com"}
	if !proxy.UrlInList("sub.example.com", "https://sub.example.com/x", patterns) {
		t.Error("expected UrlInList to match via the wildcard pattern")
	}
	if proxy.UrlInList("unlisted.com", "https://unlisted.com/x", patterns) {
		t.Error("did not expect UrlInList to match")
	}
}

func TestDomainInList(t *testing.T) {
	patterns := []string{"*.example.com", "ads.net"}
	if !proxy.DomainInList("sub.example.com", patterns) {
		t.Error("expected subdomain match")
	}
	if !proxy.DomainInList("example.com", patterns) {
		t.Error("expected bare domain from *.example.com to match")
	}
	if !proxy.DomainInList("ads.net", patterns) {
		t.Error("expected exact match")
	}
	if proxy.DomainInList("notexample.com", patterns) {
		t.Error("did not expect a bare-suffix false match")
	}
}

func TestFnmatchCharacterClass(t *testing.T) {
	if !proxy.HostMatches("a1.example.com", "a[0-9].example.com") {
		t.Error("expected character class to match")
	}
	if proxy.HostMatches("ax.example.com", "a[0-9].example.com") {
		t.Error("did not expect character class to match a non-digit")
	}
}
