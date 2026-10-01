package addons_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/categories"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func TestUrlFilterAllowShortCircuits(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://blocked.example.com/ok")
	policy := models.NewPolicy()
	policy.UrlFilter = models.UrlFilterConfig{
		Enabled: true,
		Allow:   []string{"blocked.example.com/ok"},
		Block:   []string{"*.example.com"},
	}
	fc.Policy = &policy

	addons.UrlFilter{}.HandleRequest(fc)

	if !fc.URLAllowed {
		t.Error("expected URLAllowed to short-circuit block list")
	}
	if fc.Response != nil {
		t.Error("did not expect a block response")
	}
}

func TestUrlFilterBlocksListedPattern(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://ads.example.com/track")
	policy := models.NewPolicy()
	policy.Name = "kids"
	policy.UrlFilter = models.UrlFilterConfig{Enabled: true, Block: []string{"*.example.com"}}
	fc.Policy = &policy

	addons.UrlFilter{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected a block response")
	}
	if fc.WFComponent != "url_filter" || fc.WFAction != "blocked" {
		t.Errorf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
}

func TestUrlFilterMitmPassthroughSkipsFiltering(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://ads.example.com/track")
	fc.MitmPassthrough = true
	policy := models.NewPolicy()
	policy.UrlFilter = models.UrlFilterConfig{Enabled: true, Block: []string{"*.example.com"}}
	fc.Policy = &policy

	addons.UrlFilter{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Error("expected mitm_passthrough to skip url_filter entirely")
	}
}

func TestUrlFilterCategoryBlacklist(t *testing.T) {
	rt := newTestRuntime(t)
	catDir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(catDir, "ads"), 0o755))
	must(t, os.WriteFile(filepath.Join(catDir, "ads", "domains"), []byte("ads.net\n"), 0o644))
	rt.Categories = categories.NewStore(catDir)

	fc := newFlow(t, rt, "http://sub.ads.net/x")
	policy := models.NewPolicy()
	policy.UrlFilter = models.UrlFilterConfig{Enabled: true, Mode: "blacklist", Categories: []string{"ads"}}
	fc.Policy = &policy

	addons.UrlFilter{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected category blacklist block")
	}
	if !strings.Contains(string(fc.ResponseBody), "ads") {
		t.Error("expected category name in block reason")
	}
}

func TestUrlFilterCategoryWhitelistBlocksUnlisted(t *testing.T) {
	rt := newTestRuntime(t)
	catDir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(catDir, "kids"), 0o755))
	must(t, os.WriteFile(filepath.Join(catDir, "kids", "domains"), []byte("kidsite.com\n"), 0o644))
	rt.Categories = categories.NewStore(catDir)

	fc := newFlow(t, rt, "http://random.com/x")
	policy := models.NewPolicy()
	policy.UrlFilter = models.UrlFilterConfig{Enabled: true, Mode: "whitelist", Categories: []string{"kids"}}
	fc.Policy = &policy

	addons.UrlFilter{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected whitelist mode to block a site not in the allowed category")
	}
}

func TestUrlFilterCategoryWhitelistAllowsListed(t *testing.T) {
	rt := newTestRuntime(t)
	catDir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(catDir, "kids"), 0o755))
	must(t, os.WriteFile(filepath.Join(catDir, "kids", "domains"), []byte("kidsite.com\n"), 0o644))
	rt.Categories = categories.NewStore(catDir)

	fc := newFlow(t, rt, "http://kidsite.com/x")
	policy := models.NewPolicy()
	policy.UrlFilter = models.UrlFilterConfig{Enabled: true, Mode: "whitelist", Categories: []string{"kids"}}
	fc.Policy = &policy

	addons.UrlFilter{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Error("did not expect a block for a site in the allowed category")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
