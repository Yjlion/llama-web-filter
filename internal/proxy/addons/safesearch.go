package addons

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// searchEngine mirrors safesearch.py's per-engine dict entries.
//
//   - safeParamKey/safeParamValue: injected into the request URL's query
//     string (empty key = no param-based enforcement, e.g. YouTube).
//   - safeHeaderKey/safeHeaderValue: injected as a request header (YouTube
//     Restricted Mode).
//   - safeCookieKey/safeCookieValue: overridden in the request's Cookie
//     header (Brave, which drives safe search from a cookie rather than a
//     query parameter).
//   - imageCDNDomains: hostnames that serve image results wholesale for
//     this engine, blocked outright when block_images_tab is on.
// paramMatch is a query key/value pair that identifies a search tab. Some
// engines expose the same tab through more than one URL scheme (Google's
// current unified nav uses "udm", but "tbm" still works for old links), so
// each tab category holds a list rather than a single pair.
type paramMatch struct{ key, val string }

func matchesAny(q url.Values, matches []paramMatch) bool {
	for _, m := range matches {
		if q.Get(m.key) == m.val {
			return true
		}
	}
	return false
}

type searchEngine struct {
	name            string
	domains         map[string]bool
	domainSuffix    string // e.g. ".google." (catches google.co.uk etc.)
	safeParamKey    string
	safeParamValue  string
	safeHeaderKey   string
	safeHeaderValue string
	safeCookieKey   string
	safeCookieValue string
	pathPrefix      string
	imagesPaths     []string
	videosPaths     []string
	aiDomains       map[string]bool
	aiPaths         []string
	imagesParams    []paramMatch
	videosParams    []paramMatch
	aiParams        []paramMatch
	imageCDNDomains map[string]bool
	// imageCDNPrefix/imageCDNSuffix match a sharded family of image-CDN
	// hostnames (e.g. Google load-balances thumbnails across
	// encrypted-tbn0.gstatic.com .. encrypted-tbnN.gstatic.com), where
	// imageCDNDomains' exact-match set can't enumerate every shard.
	imageCDNPrefix string
	imageCDNSuffix string
}

func isImageCDNHost(e *searchEngine, host string) bool {
	if e.imageCDNDomains[host] {
		return true
	}
	return e.imageCDNPrefix != "" && strings.HasPrefix(host, e.imageCDNPrefix) && strings.HasSuffix(host, e.imageCDNSuffix)
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

var searchEngines = []searchEngine{
	{
		name:           "google",
		domains:        set("www.google.com", "google.com"),
		domainSuffix:   ".google.",
		safeParamKey:   "safe",
		safeParamValue: "active",
		pathPrefix:     "/search",
		imagesPaths:    []string{"/imghp"},
		videosPaths:    []string{"/videohp"},
		aiDomains:      set("gemini.google.com", "bard.google.com"),
		// Google's current unified nav selects tabs via "udm" (2=Images,
		// 7=Videos, 50=AI Mode); "tbm" is the legacy scheme, still honored
		// for old links/bookmarks. Both must be checked.
		imagesParams:    []paramMatch{{"tbm", "isch"}, {"udm", "2"}},
		videosParams:    []paramMatch{{"tbm", "vid"}, {"udm", "7"}},
		aiParams:        []paramMatch{{"udm", "50"}},
		imageCDNDomains: set("encrypted-tbn0.gstatic.com"),
		imageCDNPrefix:  "encrypted-tbn",
		imageCDNSuffix:  ".gstatic.com",
	},
	{
		name:            "bing",
		domains:         set("www.bing.com", "bing.com"),
		safeParamKey:    "adlt",
		safeParamValue:  "strict",
		pathPrefix:      "/search",
		imagesPaths:     []string{"/images/"},
		videosPaths:     []string{"/videos/"},
		aiDomains:       set("copilot.microsoft.com"),
		imageCDNDomains: set("th.bing.com"),
	},
	{
		name:           "duckduckgo",
		domains:        set("duckduckgo.com", "www.duckduckgo.com", "ddg.gg"),
		safeParamKey:   "kp",
		safeParamValue: "1",
		pathPrefix:   "/",
		aiPaths:      []string{"/duckchat"},
		imagesParams: []paramMatch{{"iar", "images"}},
		videosParams: []paramMatch{{"iar", "videos"}},
	},
	{
		name:           "yahoo",
		domains:        set("search.yahoo.com"),
		domainSuffix:   ".yahoo.com",
		safeParamKey:   "vm",
		safeParamValue: "r",
		pathPrefix:     "/search",
		imagesPaths:    []string{"/images/search"},
		videosPaths:    []string{"/video/search"},
	},
	{
		name:         "brave",
		domains:      set("search.brave.com"),
		// Brave drives safe search from a cookie; the query parameter is
		// accepted too and covers the first request, before any cookie exists.
		safeParamKey:    "safesearch",
		safeParamValue:  "strict",
		safeCookieKey:   "safesearch",
		safeCookieValue: "strict",
		pathPrefix:      "/search",
		imagesPaths:     []string{"/images"},
		videosPaths:     []string{"/videos"},
		// Brave's AI answer tab lives on the search domain itself
		// (/chat redirects to /ask), so it must be scoped by path - blocking
		// the whole hostname would take plain search down with it.
		aiPaths: []string{"/ask", "/chat"},
	},
	{
		name:           "yandex",
		domains:        set("yandex.com", "www.yandex.com", "yandex.ru", "www.yandex.ru", "ya.ru"),
		domainSuffix:   ".yandex.",
		safeParamKey:   "fyandex",
		safeParamValue: "1",
		pathPrefix:     "/search",
		imagesPaths:    []string{"/images/"},
		videosPaths:    []string{"/video/"},
		aiDomains:      set("alice.yandex.ru"),
	},
	{
		name: "youtube",
		domains: set(
			"www.youtube.com", "youtube.com", "m.youtube.com",
			"music.youtube.com", "youtu.be",
		),
		domainSuffix:    ".youtube.com",
		safeHeaderKey:   "YouTube-Restrict",
		safeHeaderValue: "Strict",
		pathPrefix:      "/",
	},
}

func matchEngine(host string) *searchEngine {
	for i := range searchEngines {
		e := &searchEngines[i]
		if e.domains[host] {
			return e
		}
		if isImageCDNHost(e, host) {
			return e
		}
		if e.domainSuffix != "" && strings.Contains(host, e.domainSuffix) {
			return e
		}
		for aiDomain := range e.aiDomains {
			if host == aiDomain || strings.HasSuffix(host, "."+aiDomain) {
				return e
			}
		}
	}
	return nil
}

func safesearchShouldFilter(host string, cfg models.SafeSearchConfig) bool {
	if len(cfg.IncludeOnly) > 0 {
		return hostInList(host, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !hostInList(host, cfg.Exclude)
	}
	return true
}

func hostInList(host string, list []string) bool {
	for _, s := range list {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// SafeSearch injects per-engine safe-search parameters/headers and blocks
// images/videos/AI search tabs, ported from proxy/addons/safesearch.py.
type SafeSearch struct{}

func (SafeSearch) Name() string { return "safesearch" }

func (SafeSearch) HandleRequest(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough {
		return
	}
	policy := fc.Policy
	if policy == nil || !policy.SafeSearch.Enabled {
		return
	}

	host := fc.Request.URL.Hostname()
	cfg := policy.SafeSearch
	if !safesearchShouldFilter(host, cfg) {
		return
	}

	engine := matchEngine(host)
	if engine == nil {
		return
	}

	path := fc.Request.URL.Path

	engCfg, hasEngCfg := cfg.Engines[engine.name]
	if hasEngCfg && !engCfg.Enabled {
		return
	}
	blockImages := hasEngCfg && engCfg.BlockImagesTab
	blockVideos := hasEngCfg && engCfg.BlockVideosTab
	blockAI := hasEngCfg && engCfg.BlockAiTab

	// Image CDN domains: block wholesale when image-tab blocking is active
	// for the parent engine (every path on these hosts serves image content).
	if isImageCDNHost(engine, host) {
		if blockImages {
			fc.Block("Image search blocked by policy", "safesearch")
		}
		return
	}

	query := fc.Request.URL.Query()

	// Block AI search engines/tabs: either a dedicated AI-only domain
	// (Gemini, Copilot), a specific path on the engine's own domain
	// (DuckDuckGo's AI Chat lives at /duckchat on duckduckgo.com itself,
	// so it must be scoped by path rather than blocking the whole domain),
	// or a query param (Google's AI Mode tab, udm=50).
	if blockAI {
		for aiDomain := range engine.aiDomains {
			if host == aiDomain || strings.HasSuffix(host, "."+aiDomain) {
				fc.Block("AI search blocked by policy", "safesearch")
				return
			}
		}
		for _, p := range engine.aiPaths {
			if strings.HasPrefix(path, p) {
				fc.Block("AI search blocked by policy", "safesearch")
				return
			}
		}
		if matchesAny(query, engine.aiParams) {
			fc.Block("AI search blocked by policy", "safesearch")
			return
		}
	}

	// Block image search tab.
	if blockImages {
		for _, p := range engine.imagesPaths {
			if strings.HasPrefix(path, p) {
				fc.Block("Image search blocked by policy", "safesearch")
				return
			}
		}
		if matchesAny(query, engine.imagesParams) {
			fc.Block("Image search blocked by policy", "safesearch")
			return
		}
	}

	// Block video search tab.
	if blockVideos {
		for _, p := range engine.videosPaths {
			if strings.HasPrefix(path, p) {
				fc.Block("Video search blocked by policy", "safesearch")
				return
			}
		}
		if matchesAny(query, engine.videosParams) {
			fc.Block("Video search blocked by policy", "safesearch")
			return
		}
	}

	// Header-based enforcement (YouTube Restricted Mode) - all paths.
	if engine.safeHeaderKey != "" {
		fc.Request.Header.Set(engine.safeHeaderKey, engine.safeHeaderValue)
		fc.WFAction = "modified"
		fc.WFComponent = "safesearch"
	}

	// Cookie-based enforcement (Brave) - all paths, since the preference is
	// read on every request, not just the search one.
	if engine.safeCookieKey != "" {
		if injectCookie(fc.Request.Header, engine.safeCookieKey, engine.safeCookieValue) {
			fc.WFAction = "modified"
			fc.WFComponent = "safesearch"
		}
	}

	// URL param enforcement - paths under pathPrefix.
	if engine.safeParamKey != "" && strings.HasPrefix(path, engine.pathPrefix) {
		if injectParam(fc.Request.URL, engine.safeParamKey, engine.safeParamValue) {
			fc.WFAction = "modified"
			fc.WFComponent = "safesearch"
		}
	}
}

// injectCookie forces key=value in the request's Cookie header, leaving every
// other cookie in place, and reports whether it changed anything. A browser
// that has the preference set to something permissive sends it on every
// request, so overriding beats appending: a duplicate cookie name would leave
// the server free to pick either one.
func injectCookie(h http.Header, key, value string) bool {
	want := key + "=" + value
	raw := h.Get("Cookie")
	if strings.TrimSpace(raw) == "" {
		h.Set("Cookie", want)
		return true
	}

	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts)+1)
	found, changed := false, false
	for _, p := range parts {
		pair := strings.TrimSpace(p)
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		if strings.TrimSpace(name) != key {
			out = append(out, pair)
			continue
		}
		if found { // collapse duplicates onto the one we control
			changed = true
			continue
		}
		found = true
		if pair != want {
			changed = true
		}
		out = append(out, want)
	}
	if !found {
		out = append(out, want)
		changed = true
	}
	h.Set("Cookie", strings.Join(out, "; "))
	return changed
}

// injectParam sets key=value in u's query string, reports whether it
// changed anything. Mirrors safesearch.py's _inject_param.
func injectParam(u *url.URL, key, value string) bool {
	q := u.Query()
	if q.Get(key) == value {
		q.Set(key, value)
		u.RawQuery = q.Encode()
		return false
	}
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return true
}
