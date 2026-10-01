package addons

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/adblock"
	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// AdBlocker removes ads and trackers: requests the filter lists (or the
// model, for unknown ad-looking hosts) identify are answered with an empty
// body of the right type, and HTML pages get element-hiding CSS injected.
// Runs after UrlFilter so allow-listed URLs are never touched.
type AdBlocker struct {
	// Classifier, when set and the policy allows it, is asked about
	// third-party hosts the lists do not know.
	Classifier ContentClassifier
}

func (AdBlocker) Name() string { return "adblock" }

// empty responses by resource type, so blocked ads do not break pages.
var (
	emptyGIF = []byte{'G', 'I', 'F', '8', '9', 'a', 1, 0, 1, 0, 0x80, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x21, 0xf9, 4, 1, 0, 0, 0, 0, 0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 1, 0, 0x3b}
	emptyJS  = []byte("")
	emptyHTM = []byte("<!doctype html><html><head></head><body></body></html>")
)

func (ab AdBlocker) HandleRequest(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough || fc.Policy == nil || !fc.Policy.AdBlock.Enabled || fc.Response != nil {
		return
	}
	cfg := fc.Policy.AdBlock
	host := strings.ToLower(fc.Request.URL.Hostname())
	rawURL := fc.Request.URL.String()
	if !adBlockShouldFilter(host, rawURL, cfg) {
		return
	}
	eng := fc.Runtime.AdBlock()
	if eng == nil {
		return
	}
	h := fc.Request.Header
	req := adblock.Request{
		URL:        rawURL,
		Host:       host,
		Type:       adblock.TypeOf(fc.Request.URL, h.Get("Sec-Fetch-Dest"), h.Get("Accept"), h.Get("X-Requested-With")),
		SourceHost: adblock.SourceOf(h.Get("Referer"), h.Get("Origin")),
	}
	v := eng.Match(req)
	if v.Block {
		ab.block(fc, req.Type, "list: "+v.Rule)
		return
	}
	if v.Rule != "" {
		return // an exception rule explicitly allowed it
	}
	// Unknown host: ask the model when it is third-party and looks like an
	// ad or tracking host. The verdict is cached per host, so this is paid
	// once per host, not per request.
	if ab.Classifier == nil || !cfg.ClassifyUnknownHosts || req.SourceHost == "" || !looksAdLike(host, fc.Request.URL.Path) {
		return
	}
	if site(host) == site(req.SourceHost) {
		return
	}
	verdict := ab.Classifier.ClassifyHost(fc.Request.Context(), HostRequest{
		Host: host, SamplePaths: []string{fc.Request.URL.Path}, Budget: budgetFor(fc, 0, "host"),
	})
	if verdict.Known && verdict.Adult {
		ab.block(fc, req.Type, "model: "+verdict.Detail)
	}
}

func (AdBlocker) block(fc *proxy.FlowContext, typ adblock.Type, why string) {
	metrics.Blocks.Inc("adblock")
	if typ == adblock.TypeDocument {
		// A navigation to an ad/tracker site gets the block page, like a
		// URL-filter hit; sub-resources get a silent empty response.
		fc.Block("Blocked by ad filter ("+why+")", "adblock")
		return
	}
	var body []byte
	ctype := "text/plain"
	switch typ {
	case adblock.TypeImage:
		body, ctype = emptyGIF, "image/gif"
	case adblock.TypeScript:
		body, ctype = emptyJS, "application/javascript"
	case adblock.TypeStylesheet:
		body, ctype = emptyJS, "text/css"
	case adblock.TypeSubdocument:
		body, ctype = emptyHTM, "text/html; charset=utf-8"
	case adblock.TypeXHR:
		body, ctype = []byte("{}"), "application/json"
	default:
		body = emptyJS
	}
	fc.Response = &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type":   []string{ctype},
			"Content-Length": []string{strconv.Itoa(len(body))},
			"Cache-Control":  []string{"no-store"},
			"X-WebFilter":    []string{"adblock"},
		},
	}
	fc.ResponseBody = body
	fc.WFAction = "blocked"
	fc.WFComponent = "adblock"
}

// HandleResponse injects element-hiding CSS into HTML pages.
func (AdBlocker) HandleResponse(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough || fc.Policy == nil || !fc.Policy.AdBlock.Enabled || !fc.Policy.AdBlock.Cosmetic {
		return
	}
	if fc.Response == nil || fc.WFAction == "blocked" {
		return
	}
	ct := fc.Response.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") || len(fc.ResponseBody) == 0 {
		return
	}
	host := strings.ToLower(fc.Request.URL.Hostname())
	cfg := fc.Policy.AdBlock
	if !adBlockShouldFilter(host, fc.Request.URL.String(), cfg) {
		return
	}
	eng := fc.Runtime.AdBlock()
	if eng == nil {
		return
	}
	css := eng.CosmeticCSS(host, fc.ResponseBody)
	if css == "" {
		return
	}
	tag := []byte("<style id=\"webfilter-adblock\">\n" + css + "</style>")
	body := fc.ResponseBody
	var out []byte
	if m := reHeadOpen.FindIndex(body); m != nil {
		out = append(append(append([]byte{}, body[:m[1]]...), tag...), body[m[1]:]...)
	} else if m := reHTMLOpen.FindIndex(body); m != nil {
		out = append(append(append([]byte{}, body[:m[1]]...), tag...), body[m[1]:]...)
	} else {
		out = append(append([]byte{}, tag...), body...)
	}
	fc.ResponseBody = out
	fc.Response.Header.Set("Content-Length", strconv.Itoa(len(out)))
	if fc.WFAction == "" {
		fc.WFAction = "modified"
		fc.WFComponent = "adblock"
	}
}

var (
	reHeadOpen = regexp.MustCompile(`(?i)<head[^>]*>`)
	reHTMLOpen = regexp.MustCompile(`(?i)<html[^>]*>`)
)

func adBlockShouldFilter(host, url string, cfg models.AdBlockConfig) bool {
	if len(cfg.IncludeOnly) > 0 {
		return proxy.UrlInList(host, url, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !proxy.UrlInList(host, url, cfg.Exclude)
	}
	return true
}

// adLikeWords are host/path fragments that make an unknown third-party
// host worth asking the model about.
var adLikeWords = []string{"ads", "adserv", "advert", "banner", "sponsor", "affiliate", "track", "metric", "pixel", "beacon", "analytic", "telemetry", "doubleclick", "popunder", "promo", "click", "stats", "collect", "tag"}

func looksAdLike(host, path string) bool {
	h := strings.ToLower(host + " " + path)
	for _, w := range adLikeWords {
		if strings.Contains(h, w) {
			return true
		}
	}
	return false
}

func site(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
