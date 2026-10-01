package adblock

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

const testList = `[Adblock Plus 2.0]
! comment
||ads.example.com^
||tracker.example^$third-party
||cdn.example.com/banners/
|http://exact.example/ad.js|
/adframe.*\.html/
-ad-banner-
*$ping,third-party
||scripts.example^$script,domain=news.example|~sports.news.example
||popup.example^$popup
@@||ads.example.com/allowed/
@@||whitelisted.example^$document
||imp.example^$important
@@||imp.example^
@@||nohide.example^$generichide
###AD_300
##.ad-slot
news.example###sidebar-ad
news.example,~sports.news.example##.promo
~sports.news.example##.generic-not-on-sports
news.example#@#.ad-slot
example.com#?#div:has(> .x)
`

func engine(t *testing.T) *Engine {
	t.Helper()
	p := Parse(strings.NewReader(testList))
	if p.Skipped != 2 { // $popup and #?# are skipped
		t.Fatalf("skipped = %d, want 2", p.Skipped)
	}
	return Build(p)
}

func TestNetworkMatching(t *testing.T) {
	e := engine(t)
	cases := []struct {
		url, src string
		typ      Type
		block    bool
	}{
		{"http://ads.example.com/x.js", "", TypeScript, true},
		{"http://sub.ads.example.com/x.js", "", TypeScript, true},
		{"http://notads.example.com/x.js", "", TypeScript, false},      // label boundary
		{"http://ads.example.com/allowed/x.js", "", TypeScript, false}, // exception
		{"http://tracker.example/t.gif", "news.example", TypeImage, true},
		{"http://tracker.example/t.gif", "tracker.example", TypeImage, false}, // first-party
		{"http://tracker.example/t.gif", "", TypeImage, false},                // unknown source = first-party
		{"https://cdn.example.com/banners/1.png", "", TypeImage, true},
		{"https://cdn.example.com/images/1.png", "", TypeImage, false},
		{"http://exact.example/ad.js", "", TypeScript, true},
		{"http://exact.example/ad.js?x", "", TypeScript, false},          // end anchor
		{"http://x.example/adframe_top.html", "", TypeSubdocument, true}, // regex
		{"http://x.example/img/-ad-banner-1.png", "", TypeImage, true},
		{"http://x.example/ping", "news.example", TypePing, true},
		{"http://x.example/ping", "news.example", TypeImage, false},
		{"http://scripts.example/a.js", "news.example", TypeScript, true},
		{"http://scripts.example/a.js", "sports.news.example", TypeScript, false},
		{"http://scripts.example/a.js", "other.example", TypeScript, false},
		{"http://scripts.example/a.css", "news.example", TypeStylesheet, false},
		{"http://popup.example/x", "", TypeOther, false}, // unsupported option skipped
		{"http://imp.example/x", "", TypeOther, true},    // important beats exception
	}
	for _, c := range cases {
		u, _ := url.Parse(c.url)
		v := e.Match(Request{URL: c.url, Host: u.Hostname(), Type: c.typ, SourceHost: c.src})
		if v.Block != c.block {
			t.Errorf("%s (src=%q type=%d): block=%v want %v (rule %q)", c.url, c.src, c.typ, v.Block, c.block, v.Rule)
		}
	}
}

func TestCosmeticCSS(t *testing.T) {
	e := engine(t)
	body := []byte(`<div id="AD_300"></div><div class="x ad-slot y"></div><div class="promo"></div><span class="generic-not-on-sports"></span>`)
	css := e.CosmeticCSS("www.news.example", body)
	for _, want := range []string{"#AD_300", "#sidebar-ad", ".promo", ".generic-not-on-sports"} {
		if !strings.Contains(css, want) {
			t.Errorf("css missing %s:\n%s", want, css)
		}
	}
	if strings.Contains(css, ".ad-slot") {
		t.Errorf(".ad-slot is excepted on news.example:\n%s", css)
	}
	css = e.CosmeticCSS("sports.news.example", body)
	if strings.Contains(css, ".promo") || strings.Contains(css, ".generic-not-on-sports") {
		t.Errorf("~sports.news.example exclusions ignored:\n%s", css)
	}
	// The news.example exception covers its subdomains too; elsewhere the
	// generic selector applies when the class is present in the page.
	if css := e.CosmeticCSS("other.example", body); !strings.Contains(css, ".ad-slot") {
		t.Errorf("generic .ad-slot should apply on other.example:\n%s", css)
	}
	if css := e.CosmeticCSS("other.example", []byte(`<p>nothing here</p>`)); css != "" {
		t.Errorf("no matching ids/classes should yield no css, got %q", css)
	}
	if css := e.CosmeticCSS("nohide.example", body); strings.Contains(css, "#AD_300") {
		t.Errorf("$generichide must suppress generic selectors:\n%s", css)
	}
}

func TestTypeOfAndSourceOf(t *testing.T) {
	u, _ := url.Parse("https://x.example/a.png")
	if TypeOf(u, "", "", "") != TypeImage || TypeOf(u, "script", "", "") != TypeScript || TypeOf(u, "", "text/html,*/*", "") != TypeDocument || TypeOf(u, "empty", "", "") != TypeXHR {
		t.Error("TypeOf inference wrong")
	}
	if SourceOf("https://news.example/page?x=1", "") != "news.example" || SourceOf("", "https://o.example") != "o.example" || SourceOf("", "") != "" {
		t.Error("SourceOf wrong")
	}
}

func TestSnapshotLoadsAndMatchesKnownAdHosts(t *testing.T) {
	lists, err := LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	e := Build(lists...)
	st := e.Stats()
	t.Logf("built %d network, %d exception, %d cosmetic rules (%d skipped) from %d lists in %s", st.NetworkRules, st.Exceptions, st.CosmeticRules, st.Skipped, st.Lists, time.Since(started))
	if st.NetworkRules < 20000 || st.CosmeticRules < 10000 {
		t.Fatalf("snapshot looks truncated: %+v", st)
	}
	known := []string{
		"https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
		"https://securepubads.g.doubleclick.net/tag/js/gpt.js",
		"https://www.google-analytics.com/analytics.js",
		"https://static.criteo.net/js/ld/publishertag.js",
	}
	for _, k := range known {
		u, _ := url.Parse(k)
		v := e.Match(Request{URL: k, Host: u.Hostname(), Type: TypeScript, SourceHost: "news.example"})
		if !v.Block {
			t.Errorf("%s should be blocked by the snapshot", k)
		}
	}
	clean := []string{"https://www.wikipedia.org/", "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js", "https://www.cnn.com/index.html"}
	for _, k := range clean {
		u, _ := url.Parse(k)
		v := e.Match(Request{URL: k, Host: u.Hostname(), Type: TypeDocument})
		if v.Block {
			t.Errorf("%s should not be blocked (rule %q)", k, v.Rule)
		}
	}
	// Throughput sanity: a few thousand lookups must take well under a second.
	started = time.Now()
	n := 5000
	for i := 0; i < n; i++ {
		k := clean[i%len(clean)]
		u, _ := url.Parse(k)
		e.Match(Request{URL: k + "?i=" + string(rune('a'+i%26)), Host: u.Hostname(), Type: TypeScript, SourceHost: "news.example"})
	}
	per := time.Since(started) / time.Duration(n)
	t.Logf("%d lookups, %s each", n, per)
	if per > 200*time.Microsecond {
		t.Errorf("lookup too slow: %s per request", per)
	}
}
