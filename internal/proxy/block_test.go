package proxy_test

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

func newTestFlow(t *testing.T, uiLanguage string) *proxy.FlowContext {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "webfilter.db")
	logs, err := logstore.Configure(dbPath, 30, true, true)
	if err != nil {
		t.Fatalf("logstore.Configure: %v", err)
	}
	t.Cleanup(func() { logs.Close() })

	rt := &state.Runtime{Logs: logs}
	cfg := *rt.Settings()
	cfg.UILanguage = uiLanguage
	rt.SetSettings(cfg)

	u, _ := url.Parse("https://blocked.example.com/some/path")
	req := &http.Request{URL: u, Host: "blocked.example.com"}

	policy := models.NewPolicy()
	policy.Name = "kids"
	policy.BlockPage.Message = "Ask a parent to unblock this."

	return &proxy.FlowContext{
		Runtime:  rt,
		ClientIP: "192.168.1.50",
		Request:  req,
		Policy:   &policy,
	}
}

func TestBlockSetsResponseAndMetadata(t *testing.T) {
	fc := newTestFlow(t, "en")
	fc.Block("Adult content detected", "text_classifier")

	if fc.Response == nil {
		t.Fatal("expected fc.Response to be set")
	}
	if fc.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", fc.Response.StatusCode)
	}
	if ct := fc.Response.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if fc.WFAction != "blocked" || fc.WFComponent != "text_classifier" {
		t.Errorf("WFAction/WFComponent = %q/%q, want blocked/text_classifier", fc.WFAction, fc.WFComponent)
	}

	html := string(fc.ResponseBody)
	if !strings.Contains(html, "Access Blocked") {
		t.Error("expected English title in rendered HTML")
	}
	if !strings.Contains(html, "blocked.example.com") {
		t.Error("expected domain in rendered HTML")
	}
	if !strings.Contains(html, "Adult content detected") {
		t.Error("expected reason text in rendered HTML")
	}
	if !strings.Contains(html, "Ask a parent to unblock this.") {
		t.Error("expected custom block-page message in rendered HTML")
	}
	if !strings.Contains(html, "kids") {
		t.Error("expected policy name in rendered HTML")
	}
	if !strings.Contains(html, `dir="ltr"`) {
		t.Error("expected ltr direction for English")
	}
}

func TestBlockLocalizesAndSetsRTL(t *testing.T) {
	fc := newTestFlow(t, "he")
	fc.Block("URL blocked by policy", "url_filter")

	html := string(fc.ResponseBody)
	if !strings.Contains(html, `dir="rtl"`) {
		t.Error("expected rtl direction for Hebrew")
	}
	if !strings.Contains(html, "הגישה נחסמה") {
		t.Error("expected Hebrew title")
	}
}

func TestBlockFallsBackToEnglishForUnknownLanguage(t *testing.T) {
	fc := newTestFlow(t, "xx")
	fc.Block("blocked", "url_filter")

	html := string(fc.ResponseBody)
	if !strings.Contains(html, "Access Blocked") {
		t.Error("expected English fallback for an unrecognized ui_language")
	}
}

func TestLogBlockDoesNotSetResponse(t *testing.T) {
	fc := newTestFlow(t, "en")
	fc.LogBlock("YouTube channel blocked", "youtube")

	if fc.Response != nil {
		t.Error("LogBlock should not set a response - callers that mutate JSON in place use this alone")
	}
	if fc.WFAction != "blocked" || fc.WFComponent != "youtube" {
		t.Errorf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
}
