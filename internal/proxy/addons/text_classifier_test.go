package addons_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func TestTextClassifierBlocksOnKeywordThreshold(t *testing.T) {
	rt := newTestRuntime(t)
	// Repeat the padding so the stripped text clears the 100-char floor,
	// and include >= minKeywordHits (3) distinct high-precision keywords.
	html := "<html><body>" + strings.Repeat("filler content here to pad the page. ", 5) +
		"This site has porn and hentai and xxx content everywhere.</body></html>"
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}}
	fc.ResponseBody = []byte(html)
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	fc.Policy = &policy

	addons.TextClassifier{}.HandleResponse(fc)

	if fc.Response.StatusCode != http.StatusOK || !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Fatalf("expected a block page, got status=%d body=%s", fc.Response.StatusCode, fc.ResponseBody)
	}
}

func TestTextClassifierAllowsBenignPage(t *testing.T) {
	rt := newTestRuntime(t)
	html := "<html><body>" + strings.Repeat("Welcome to our lovely gardening blog. ", 5) + "</body></html>"
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}}
	fc.ResponseBody = []byte(html)
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	fc.Policy = &policy

	original := string(fc.ResponseBody)
	addons.TextClassifier{}.HandleResponse(fc)

	if string(fc.ResponseBody) != original {
		t.Error("did not expect a benign page to be blocked")
	}
}

func TestTextClassifierBlocksTinyPageWithMultipleKeywordHits(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	fc.ResponseBody = []byte("<html>porn xxx hentai</html>")
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	fc.Policy = &policy

	addons.TextClassifier{}.HandleResponse(fc)

	if !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Error("expected tiny page with multiple high-confidence keyword hits to be blocked")
	}
}

func TestTextClassifierSkipsTinyPageWithWeakEvidence(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	fc.ResponseBody = []byte("<html>single mention of porn</html>")
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	fc.Policy = &policy

	original := string(fc.ResponseBody)
	addons.TextClassifier{}.HandleResponse(fc)

	if string(fc.ResponseBody) != original {
		t.Error("expected tiny page with weak evidence to be skipped")
	}
}

func TestTextClassifierIgnoresNonHTML(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/page.json")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}}
	fc.ResponseBody = []byte(`{"text": "porn xxx hentai nude naked erotic"}`)
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	fc.Policy = &policy

	original := string(fc.ResponseBody)
	addons.TextClassifier{}.HandleResponse(fc)

	if string(fc.ResponseBody) != original {
		t.Error("expected non-HTML content types to be skipped")
	}
}

func TestTextClassifierMLScorerUsedBelowKeywordThreshold(t *testing.T) {
	rt := newTestRuntime(t)
	html := "<html><body>" + strings.Repeat("This page mentions nude content once. ", 5) + "</body></html>"
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	fc.ResponseBody = []byte(html)
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	policy.TextClassifier.Threshold = 0.5
	fc.Policy = &policy

	tc := addons.TextClassifier{Scorer: stubScorer{score: 0.9}}
	tc.HandleResponse(fc)

	if !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Error("expected the ML scorer to push a single-keyword-hit page over threshold")
	}
}

func TestTextClassifierMLScorerBlocksBelowKeywordThreshold(t *testing.T) {
	rt := newTestRuntime(t)
	html := "<html><body>" + strings.Repeat("Browse adult video galleries and live webcam shows. ", 3) + "</body></html>"
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	fc.ResponseBody = []byte(html)
	policy := models.NewPolicy()
	policy.TextClassifier = models.NewTextClassifierConfig()
	policy.TextClassifier.Enabled = true
	policy.TextClassifier.Threshold = 0.8
	fc.Policy = &policy

	tc := addons.TextClassifier{Scorer: stubScorer{score: 0.95}}
	tc.HandleResponse(fc)

	if !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Error("expected the ML scorer to block adult text below the keyword pre-filter threshold")
	}
}

func TestTextClassifierIncludeOnlyAndExcludeStillGateScoring(t *testing.T) {
	rt := newTestRuntime(t)
	html := "<html><body>" + strings.Repeat("adult video galleries and live webcam shows. ", 4) + "</body></html>"
	for _, tc := range []struct {
		name string
		cfg  func(*models.Policy)
	}{
		{
			name: "exclude",
			cfg:  func(p *models.Policy) { p.TextClassifier.Exclude = []string{"example.com"} },
		},
		{
			name: "include_only_miss",
			cfg:  func(p *models.Policy) { p.TextClassifier.IncludeOnly = []string{"other.example"} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFlow(t, rt, "http://example.com/page")
			fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
			fc.ResponseBody = []byte(html)
			policy := models.NewPolicy()
			policy.TextClassifier = models.NewTextClassifierConfig()
			policy.TextClassifier.Enabled = true
			tc.cfg(&policy)
			fc.Policy = &policy
			original := string(fc.ResponseBody)

			addons.TextClassifier{Scorer: stubScorer{score: 0.99}}.HandleResponse(fc)

			if string(fc.ResponseBody) != original {
				t.Fatal("expected include/exclude gating to skip text classification")
			}
		})
	}
}

type stubScorer struct{ score float64 }

func (s stubScorer) Score(text string) (float64, bool) { return s.score, true }
