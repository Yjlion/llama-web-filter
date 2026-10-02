package addons_test

import (
	"context"
	"sync"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// fakeCategorizer answers from a fixed map and records every lookup.
type fakeCategorizer struct {
	mu      sync.Mutex
	known   map[string]string
	timeout bool
	down    bool
	asked   []state.CategoryLookup
}

func (f *fakeCategorizer) Categorize(_ context.Context, q state.CategoryLookup) state.CategoryAnswer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, q)
	if c, ok := f.known[q.Host]; ok {
		return state.CategoryAnswer{Category: c, Known: true, Source: "llm"}
	}
	if !q.Enqueue {
		return state.CategoryAnswer{}
	}
	if f.down {
		return state.CategoryAnswer{Unavailable: true}
	}
	return state.CategoryAnswer{TimedOut: f.timeout}
}

func categoryFlow(t *testing.T, cat *fakeCategorizer, url string, nav bool, cfg models.CategoryFilterConfig) *proxy.FlowContext {
	t.Helper()
	rt := newTestRuntime(t)
	rt.SetSiteCategorizer(cat)
	fc := newFlow(t, rt, url)
	if nav {
		fc.Request.Header.Set("Sec-Fetch-Dest", "document")
	} else {
		fc.Request.Header.Set("Sec-Fetch-Dest", "script")
	}
	p := models.NewPolicy()
	cfg.Enabled = true
	p.CategoryFilter = cfg
	fc.Policy = &p
	return fc
}

func blockList(cats ...string) models.CategoryFilterConfig {
	c := models.NewCategoryFilterConfig()
	c.Categories = cats
	return c
}

func TestCategoryFilterBlocksListedCategoryOnNavigation(t *testing.T) {
	cat := &fakeCategorizer{known: map[string]string{"shop.example": "shopping", "news.example": "news"}}
	fc := categoryFlow(t, cat, "http://shop.example/", true, blockList("shopping"))
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.WFAction != "blocked" || fc.WFComponent != "category_filter" {
		t.Fatalf("shopping not blocked: %q/%q", fc.WFAction, fc.WFComponent)
	}
	if len(cat.asked) != 1 || !cat.asked[0].Enqueue || cat.asked[0].Budget <= 0 {
		t.Fatalf("navigation lookup = %+v", cat.asked)
	}

	fc = categoryFlow(t, cat, "http://news.example/", true, blockList("shopping"))
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("news blocked")
	}
}

func TestCategoryFilterSubresourcesNeverAskTheModel(t *testing.T) {
	cat := &fakeCategorizer{known: map[string]string{"social.example": "social_media"}}
	fc := categoryFlow(t, cat, "http://cdn.unknown.example/a.js", false, blockList("social_media"))
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response != nil || cat.asked[0].Enqueue || cat.asked[0].Budget != 0 {
		t.Fatalf("sub-resource lookup = %+v blocked=%v", cat.asked, fc.Response != nil)
	}
	// A known blocked category is still refused as a sub-resource.
	fc = categoryFlow(t, cat, "http://social.example/widget.js", false, blockList("social_media"))
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response == nil {
		t.Fatal("known social sub-resource allowed")
	}
}

func TestCategoryFilterWhitelist(t *testing.T) {
	cat := &fakeCategorizer{known: map[string]string{"edu.example": "education", "game.example": "gaming",
		"cdn.example": "infrastructure", "other.example": "other"}}
	cfg := blockList("education")
	cfg.Mode = models.UrlFilterModeWhitelist
	for url, wantBlocked := range map[string]bool{
		"http://edu.example/": false, "http://game.example/": true, "http://cdn.example/": false,
	} {
		fc := categoryFlow(t, cat, url, true, cfg)
		addons.CategoryFilter{}.HandleRequest(fc)
		if (fc.Response != nil) != wantBlocked {
			t.Errorf("%s blocked=%v want %v", url, fc.Response != nil, wantBlocked)
		}
	}
	// Sub-resources in allow-only mode pass whatever their category.
	fc := categoryFlow(t, cat, "http://other.example/x.js", false, cfg)
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response != nil {
		t.Error("whitelist blocked a sub-resource")
	}
}

func TestCategoryFilterFallbacks(t *testing.T) {
	cfg := blockList("shopping")
	cfg.OnTimeout = models.FallbackBlock
	fc := categoryFlow(t, &fakeCategorizer{timeout: true}, "http://new.example/", true, cfg)
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response == nil {
		t.Error("on_timeout=block did not block")
	}
	fc = categoryFlow(t, &fakeCategorizer{timeout: true}, "http://new.example/", true, blockList("shopping"))
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response != nil {
		t.Error("default on_timeout should allow")
	}
	cfg = blockList("shopping")
	cfg.OnUnavailable = models.FallbackBlock
	fc = categoryFlow(t, &fakeCategorizer{down: true}, "http://new.example/", true, cfg)
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response == nil {
		t.Error("on_unavailable=block did not block")
	}
}

func TestCategoryFilterAllowListWins(t *testing.T) {
	cat := &fakeCategorizer{known: map[string]string{"shop.example": "shopping"}}
	fc := categoryFlow(t, cat, "http://shop.example/", true, blockList("shopping"))
	fc.URLAllowed = true
	addons.CategoryFilter{}.HandleRequest(fc)
	if fc.Response != nil || len(cat.asked) != 0 {
		t.Fatal("allow-listed URL was categorized or blocked")
	}
}
