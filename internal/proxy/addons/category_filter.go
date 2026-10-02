package addons

import (
	"strings"

	"github.com/yjlion/llama-web-filter/internal/adblock"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

// CategoryFilter blocks or allows websites by category (shopping, news,
// social media, banking, ...). The category comes from the installed domain
// lists when they know the site, otherwise from the edge LLM, cached per
// site (see the SiteCategorizer on the runtime).
//
// Only top-level navigations ask the model and wait for it, within the
// policy's budget; a first visit that outlasts the budget gets on_timeout.
// Sub-resources are judged from what is already known and never queue a
// model call, so one page's dozens of CDN and API hosts cannot flood it.
type CategoryFilter struct{}

func (CategoryFilter) Name() string { return "category_filter" }

func (CategoryFilter) HandleRequest(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough || fc.Policy == nil || fc.Response != nil {
		return
	}
	cfg := fc.Policy.CategoryFilter
	if !cfg.Enabled || (cfg.Mode != models.UrlFilterModeWhitelist && len(cfg.Categories) == 0) {
		return
	}
	h := fc.Request.Header
	nav := adblock.TypeOf(fc.Request.URL, h.Get("Sec-Fetch-Dest"), h.Get("Accept"), h.Get("X-Requested-With")) == adblock.TypeDocument
	host := strings.ToLower(fc.Request.URL.Hostname())

	cat := fc.Runtime.SiteCategorizer()
	var ans state.CategoryAnswer
	if cat == nil {
		ans.Unavailable = true
	} else {
		q := state.CategoryLookup{Host: host, Enqueue: nav}
		if nav {
			q.Budget = budgetFor(fc, cfg.BudgetMs, "category")
		}
		ans = cat.Categorize(fc.Request.Context(), q)
	}

	switch {
	case ans.Known:
		// In allow-only mode a sub-resource is never refused for its
		// category: the page it belongs to was already allowed, and the
		// hosts it pulls from are mostly CDNs the model may file as "other".
		if !nav && cfg.Mode == models.UrlFilterModeWhitelist {
			return
		}
		if cfg.Blocks(ans.Category) {
			if cfg.Mode == models.UrlFilterModeWhitelist {
				fc.Block("Site category '"+sitecat.Label(ans.Category)+"' is not in the allowed categories", "category_filter")
			} else {
				fc.Block("Site category '"+sitecat.Label(ans.Category)+"' blocked by policy", "category_filter")
			}
		}
	case !nav:
		// Unknown sub-resource: allow.
	case ans.TimedOut:
		if cfg.OnTimeout == models.FallbackBlock {
			fc.Block("Site not categorized yet (the model is still deciding; try again shortly)", "category_filter")
		}
	default:
		if cfg.OnUnavailable == models.FallbackBlock {
			fc.Block("Site category unavailable (the model is not running)", "category_filter")
		}
	}
}
