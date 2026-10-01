package addons_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func enabledPolicyWithSafeSearch(engineOverrides map[string]models.SafeSearchEngineConfig) models.Policy {
	p := models.NewPolicy()
	cfg := models.NewSafeSearchConfig()
	cfg.Enabled = true
	for name, e := range engineOverrides {
		cfg.Engines[name] = e
	}
	p.SafeSearch = cfg
	return p
}

func TestSafeSearchGoogleParamInjection(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://www.google.com/search?q=cats")
	policy := enabledPolicyWithSafeSearch(nil)
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if got := fc.Request.URL.Query().Get("safe"); got != "active" {
		t.Errorf("safe param = %q, want active", got)
	}
	if fc.WFAction != "modified" || fc.WFComponent != "safesearch" {
		t.Errorf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
}

func TestSafeSearchYouTubeHeaderInjection(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://www.youtube.com/watch?v=abc")
	policy := enabledPolicyWithSafeSearch(nil)
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if got := fc.Request.Header.Get("YouTube-Restrict"); got != "Strict" {
		t.Errorf("YouTube-Restrict header = %q, want Strict", got)
	}
}

func TestSafeSearchBlocksImageTab(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://www.google.com/search?tbm=isch&q=cats")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: true, BlockImagesTab: true},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected image tab param to trigger a block")
	}
}

func TestSafeSearchBlocksGoogleAiModeTab(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://www.google.com/search?udm=50&q=cats")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: true, BlockAiTab: true},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected Google AI Mode (udm=50) to trigger a block")
	}
}

func TestSafeSearchBlocksGoogleUdmImagesAndVideosTabs(t *testing.T) {
	rt := newTestRuntime(t)
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: true, BlockImagesTab: true, BlockVideosTab: true},
	})

	rt2 := newTestRuntime(t)
	fcImages := newFlow(t, rt, "http://www.google.com/search?udm=2&q=cats")
	fcImages.Policy = &policy
	addons.SafeSearch{}.HandleRequest(fcImages)
	if fcImages.Response == nil {
		t.Error("expected Google Images tab (udm=2) to trigger a block")
	}

	fcVideos := newFlow(t, rt2, "http://www.google.com/search?udm=7&q=cats")
	fcVideos.Policy = &policy
	addons.SafeSearch{}.HandleRequest(fcVideos)
	if fcVideos.Response == nil {
		t.Error("expected Google Videos tab (udm=7) to trigger a block")
	}
}

func TestSafeSearchBlocksImageCDNWholesale(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://encrypted-tbn0.gstatic.com/images?q=x")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: true, BlockImagesTab: true},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected the google image CDN to be blocked wholesale")
	}
}

func TestSafeSearchBlocksImageCDNShardedHosts(t *testing.T) {
	rt := newTestRuntime(t)
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: true, BlockImagesTab: true},
	})

	for _, host := range []string{"encrypted-tbn1.gstatic.com", "encrypted-tbn2.gstatic.com", "encrypted-tbn3.gstatic.com"} {
		fc := newFlow(t, rt, "http://"+host+"/images?q=x")
		fc.Policy = &policy

		addons.SafeSearch{}.HandleRequest(fc)

		if fc.Response == nil {
			t.Errorf("expected %s to be blocked wholesale like encrypted-tbn0", host)
		}
	}
}

func TestSafeSearchEngineDisabledSkipsEnforcement(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://www.google.com/search?q=cats")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: false},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Request.URL.Query().Get("safe") != "" {
		t.Error("did not expect safe param injection for a disabled engine")
	}
}

func TestSafeSearchDuckDuckGoBlockAiTabDoesNotBlockPlainSearch(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://duckduckgo.com/?q=cats")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"duckduckgo": {Enabled: true, BlockAiTab: true},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Fatal("plain DuckDuckGo search must not be blocked by block_ai_tab")
	}
	if got := fc.Request.URL.Query().Get("kp"); got != "1" {
		t.Errorf("kp param = %q, want 1", got)
	}
}

func TestSafeSearchDuckDuckGoBlocksAiChatPath(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://duckduckgo.com/duckchat?q=hi")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"duckduckgo": {Enabled: true, BlockAiTab: true},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected DuckDuckGo AI chat path to be blocked")
	}
}

func TestSafeSearchUnlistedEngineIsNoop(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://unrelated.com/search?q=cats")
	policy := enabledPolicyWithSafeSearch(nil)
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response != nil || fc.WFAction != "" {
		t.Error("expected no effect for a domain matching no known search engine")
	}
}

// ---------------------------------------------------------------------------
// Brave
// ---------------------------------------------------------------------------

// Brave reads safe search from a cookie; the query param is accepted too and
// covers the first request, before the browser has any cookie to send.
func TestSafeSearchBraveInjectsParamAndCookie(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://search.brave.com/search?q=cats")
	policy := enabledPolicyWithSafeSearch(nil)
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if got := fc.Request.URL.Query().Get("safesearch"); got != "strict" {
		t.Errorf("safesearch param = %q, want strict", got)
	}
	if got := fc.Request.Header.Get("Cookie"); got != "safesearch=strict" {
		t.Errorf("Cookie = %q, want safesearch=strict", got)
	}
	if fc.WFAction != "modified" || fc.WFComponent != "safesearch" {
		t.Errorf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
}

// A browser that already has the preference set to "off" must be overridden,
// not appended to - a duplicate cookie name would let the server pick either.
func TestSafeSearchBraveOverridesExistingCookie(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://search.brave.com/search?q=cats")
	fc.Request.Header.Set("Cookie", "sid=abc; safesearch=off; theme=dark")
	policy := enabledPolicyWithSafeSearch(nil)
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	got := fc.Request.Header.Get("Cookie")
	if got != "sid=abc; safesearch=strict; theme=dark" {
		t.Errorf("Cookie = %q, want the safesearch value replaced in place", got)
	}
}

// Already-strict traffic must not be reported as modified.
func TestSafeSearchBraveCookieAlreadyStrictIsNotAChange(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://search.brave.com/?q=cats")
	fc.Request.Header.Set("Cookie", "safesearch=strict")
	policy := enabledPolicyWithSafeSearch(nil)
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.WFAction == "modified" {
		t.Error("an already-strict cookie on a non-search path should not count as a modification")
	}
}

// Brave's AI tab lives at /ask on the search domain itself, so it must be
// scoped by path - the DuckDuckGo/Google regression shape.
func TestSafeSearchBraveBlocksAskPathButNotPlainSearch(t *testing.T) {
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"brave": {Enabled: true, BlockAiTab: true},
	})

	rt := newTestRuntime(t)
	ai := newFlow(t, rt, "http://search.brave.com/ask?q=cats")
	ai.Policy = &policy
	addons.SafeSearch{}.HandleRequest(ai)
	if ai.Response == nil {
		t.Error("expected /ask to be blocked when block_ai_tab is on")
	}

	plain := newFlow(t, rt, "http://search.brave.com/search?q=cats")
	plain.Policy = &policy
	addons.SafeSearch{}.HandleRequest(plain)
	if plain.Response != nil {
		t.Error("plain /search must stay allowed when only the AI tab is blocked")
	}
}

func TestSafeSearchBraveBlocksImagesAndVideosTabs(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"images", "http://search.brave.com/images?q=cats"},
		{"videos", "http://search.brave.com/videos?q=cats"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t)
			fc := newFlow(t, rt, tc.url)
			policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
				"brave": {Enabled: true, BlockImagesTab: true, BlockVideosTab: true},
			})
			fc.Policy = &policy

			addons.SafeSearch{}.HandleRequest(fc)

			if fc.Response == nil {
				t.Errorf("expected %s tab to be blocked", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Yandex
// ---------------------------------------------------------------------------

func TestSafeSearchYandexParamInjection(t *testing.T) {
	for _, host := range []string{"yandex.com", "yandex.ru", "www.yandex.com"} {
		t.Run(host, func(t *testing.T) {
			rt := newTestRuntime(t)
			fc := newFlow(t, rt, "http://"+host+"/search/?text=cats")
			policy := enabledPolicyWithSafeSearch(nil)
			fc.Policy = &policy

			addons.SafeSearch{}.HandleRequest(fc)

			if got := fc.Request.URL.Query().Get("fyandex"); got != "1" {
				t.Errorf("fyandex param = %q, want 1", got)
			}
		})
	}
}

func TestSafeSearchYandexBlocksImagesAndVideoTabs(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"images", "http://yandex.com/images/search?text=cats"},
		{"video", "http://yandex.com/video/search?text=cats"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t)
			fc := newFlow(t, rt, tc.url)
			policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
				"yandex": {Enabled: true, BlockImagesTab: true, BlockVideosTab: true},
			})
			fc.Policy = &policy

			addons.SafeSearch{}.HandleRequest(fc)

			if fc.Response == nil {
				t.Errorf("expected %s tab to be blocked", tc.name)
			}
		})
	}
}

// Alice is Yandex's AI assistant and lives on its own domain, so unlike
// Brave's /ask it is matched by hostname.
func TestSafeSearchYandexBlocksAliceDomain(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://alice.yandex.ru/")
	policy := enabledPolicyWithSafeSearch(map[string]models.SafeSearchEngineConfig{
		"yandex": {Enabled: true, BlockAiTab: true},
	})
	fc.Policy = &policy

	addons.SafeSearch{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Error("expected alice.yandex.ru to be blocked when block_ai_tab is on")
	}
}
