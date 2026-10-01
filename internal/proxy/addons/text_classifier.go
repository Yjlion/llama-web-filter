package addons

import (
	"github.com/yjlion/llama-web-filter/internal/classify/textextract"
	"regexp"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// TextClassifier detects adult text content via a fast keyword
// pre-filter (always active, zero dependencies) plus the LLM verdict
// stage behind ContentClassifier.
type TextClassifier struct {
	// Classifier is the verdict backend; nil means keyword-only.
	Classifier ContentClassifier
	// Prefetcher, when set, pre-scores the images a page references so the
	// image classifier serves them from cache. Gated on the policy's
	// image_classifier.prefetch.
	Prefetcher ImagePrefetcher
}

func (TextClassifier) Name() string { return "text_classifier" }

// adultKeywordsRe is a conservative, high-precision keyword pre-filter,
// ported verbatim from text_classifier.py's _ADULT_KEYWORDS.
var adultKeywordsRe = regexp.MustCompile(`(?i)\b(porn|pornography|xxx|hentai|nude|naked|erotic|masturbat|orgasm|` +
	`penis|vagina|anal sex|oral sex|blowjob|handjob|gangbang|threesome|` +
	`escort service|cam girl|onlyfans|nsfw|adult content)\b`)

// minKeywordHits requires multiple hits to reduce false positives.
const minKeywordHits = 3

// KeywordScore exposes the keyword pre-filter to the management API's URL
// scanner, so a Tools verdict and a live proxy verdict can't drift apart.
// 1.0 means "enough hits to block on keywords alone".
func KeywordScore(text string) float64 { return keywordScore(text) }

// StripHTML exposes the same tag-stripping the response path uses.
func StripHTML(html string) string { return stripHTML(html) }

func keywordScore(text string) float64 {
	hits := len(adultKeywordsRe.FindAllString(text, -1))
	score := float64(hits) / float64(minKeywordHits)
	if score > 1.0 {
		return 1.0
	}
	return score
}

func textClassifierShouldFilter(host, url string, cfg models.TextClassifierConfig) bool {
	if len(cfg.IncludeOnly) > 0 {
		return proxy.UrlInList(host, url, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !proxy.UrlInList(host, url, cfg.Exclude)
	}
	return true
}

// htmlTagRe strips HTML tags without a full parser - the same
// no-dependency fallback text_classifier.py itself falls back to when
// BeautifulSoup isn't installed.
var htmlTagRe = regexp.MustCompile(`<[^>]+>`)

func stripHTML(html string) string {
	return htmlTagRe.ReplaceAllString(html, " ")
}

func (tc TextClassifier) HandleResponse(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough {
		return
	}
	policy := fc.Policy
	if policy == nil || fc.Response == nil {
		return
	}
	ct := fc.Response.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return
	}
	host := fc.Request.URL.Hostname()
	url := fc.Request.URL.String()

	// Speculative image pre-scoring is independent of the text verdict: it
	// only needs the page's image references.
	if tc.Prefetcher != nil && policy.ImageClassifier.Enabled && policy.ImageClassifier.Prefetch &&
		imageClassifierShouldFilter(host, url, policy.ImageClassifier) {
		if page := textextract.Extract(fc.ResponseBody); len(page.ImageURLs) > 0 {
			tc.Prefetcher.Prefetch(fc.Request.URL, page.ImageURLs, prefetchLimit, fc.Request.Header)
		}
	}

	if !policy.TextClassifier.Enabled {
		return
	}
	cfg := policy.TextClassifier
	if !textClassifierShouldFilter(host, url, cfg) {
		return
	}

	page := textextract.Extract(fc.ResponseBody)
	text := page.Summary()
	if keywordScore(page.Title+" "+text) >= 1.0 {
		metrics.ObserveClassifier("text", time.Now(), metrics.ResultNSFW)
		fc.Block("Adult text content detected", "text_classifier")
		return
	}
	if len(text) < 100 || tc.Classifier == nil { // skip tiny pages
		return
	}

	started := time.Now()
	v := tc.Classifier.ClassifyText(fc.Request.Context(), TextRequest{
		URL: url, Title: page.Title, Text: text, Budget: budgetFor(fc, cfg.BudgetMs, "text"),
	})
	switch {
	case v.Known:
		adult := v.Adult || v.Score >= cfg.Threshold
		if adult {
			metrics.ObserveClassifier("text", started, metrics.ResultNSFW)
			fc.Block("Adult text content detected", "text_classifier")
		} else {
			metrics.ObserveClassifier("text", started, metrics.ResultClean)
		}
	case v.TimedOut:
		metrics.ObserveClassifier("text", started, metrics.ResultTimeout)
		if cfg.OnTimeout == models.FallbackBlock {
			fc.Block("Page is being checked; try again in a moment", "text_classifier")
		}
	default:
		metrics.ObserveClassifier("text", started, metrics.ResultError)
		if cfg.OnUnavailable == models.FallbackBlock {
			fc.Block("Content classification unavailable", "text_classifier")
		}
	}
}

// prefetchLimit caps how many of a page's images are pre-scored.
const prefetchLimit = 12
