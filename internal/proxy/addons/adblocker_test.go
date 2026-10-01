package addons_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/adblock"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

const adTestList = `||ads.example^
||tracker.example^$third-party
###AD_300
news.example##.sidebar-promo
@@||ads.example/allowed/
`

func adRuntime(t *testing.T) *state.Runtime {
	rt := newTestRuntime(t)
	rt.SetAdBlockForTest(adblock.Build(adblock.Parse(strings.NewReader(adTestList))))
	return rt
}

func adPolicy() *models.Policy {
	p := models.NewPolicy()
	p.Name = "default"
	p.AdBlock.Enabled = true
	return &p
}

type hostStub struct{ ad bool }

func (h hostStub) ClassifyText(context.Context, addons.TextRequest) addons.Verdict {
	return addons.Verdict{Known: true}
}
func (h hostStub) ClassifyImage(context.Context, addons.ImageRequest) addons.Verdict {
	return addons.Verdict{Known: true}
}
func (h hostStub) ClassifyHost(_ context.Context, req addons.HostRequest) addons.Verdict {
	return addons.Verdict{Known: true, Adult: h.ad, Detail: "stub"}
}

func TestAdBlockerBlocksListedRequestsWithTypedEmptyBodies(t *testing.T) {
	rt := adRuntime(t)
	ab := addons.AdBlocker{}

	fc := newFlow(t, rt, "http://ads.example/pixel.gif")
	fc.Request.Header.Set("Referer", "http://news.example/")
	fc.Policy = adPolicy()
	ab.HandleRequest(fc)
	if fc.Response == nil || fc.Response.Header.Get("Content-Type") != "image/gif" || fc.WFAction != "blocked" || fc.WFComponent != "adblock" {
		t.Fatalf("image ad should get an empty gif: %+v", fc.Response)
	}

	fc = newFlow(t, rt, "http://ads.example/ad.js")
	fc.Request.Header.Set("Sec-Fetch-Dest", "script")
	fc.Policy = adPolicy()
	ab.HandleRequest(fc)
	if fc.Response == nil || fc.Response.Header.Get("Content-Type") != "application/javascript" || len(fc.ResponseBody) != 0 {
		t.Fatalf("script ad should get an empty js body: %+v", fc.Response)
	}

	// Exception rule.
	fc = newFlow(t, rt, "http://ads.example/allowed/x.js")
	fc.Policy = adPolicy()
	ab.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("exception rule must allow the request")
	}

	// Third-party only: same site is allowed.
	fc = newFlow(t, rt, "http://tracker.example/t.js")
	fc.Request.Header.Set("Referer", "http://www.tracker.example/page")
	fc.Policy = adPolicy()
	ab.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("first-party request must not match a $third-party rule")
	}

	// Navigation to an ad host gets the block page.
	fc = newFlow(t, rt, "http://ads.example/")
	fc.Request.Header.Set("Sec-Fetch-Dest", "document")
	fc.Policy = adPolicy()
	ab.HandleRequest(fc)
	if fc.Response == nil || !strings.Contains(string(fc.ResponseBody), "Access Blocked") {
		t.Fatal("document navigation to an ad host should render the block page")
	}

	// Disabled policy or excluded site: untouched.
	fc = newFlow(t, rt, "http://ads.example/pixel.gif")
	p := adPolicy()
	p.AdBlock.Exclude = []string{"ads.example"}
	fc.Policy = p
	ab.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("excluded site must not be filtered")
	}
}

func TestAdBlockerAsksModelAboutUnknownAdLikeHosts(t *testing.T) {
	rt := adRuntime(t)
	fc := newFlow(t, rt, "http://metrics.unknown.example/collect?id=1")
	fc.Request.Header.Set("Referer", "http://news.example/")
	fc.Request.Header.Set("Sec-Fetch-Dest", "empty")
	fc.Policy = adPolicy()
	addons.AdBlocker{Classifier: hostStub{ad: true}}.HandleRequest(fc)
	if fc.Response == nil || fc.Response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("model verdict should block the xhr with an empty json body: %+v", fc.Response)
	}

	fc = newFlow(t, rt, "http://metrics.unknown.example/collect?id=1")
	fc.Request.Header.Set("Referer", "http://news.example/")
	fc.Policy = adPolicy()
	addons.AdBlocker{Classifier: hostStub{ad: false}}.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("a clean model verdict must not block")
	}

	// Not ad-like, or first-party: the model is never asked.
	fc = newFlow(t, rt, "http://cdn.unknown.example/app.js")
	fc.Request.Header.Set("Referer", "http://news.example/")
	fc.Policy = adPolicy()
	addons.AdBlocker{Classifier: hostStub{ad: true}}.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("hosts that do not look like ad servers are not sent to the model")
	}
	p := adPolicy()
	p.AdBlock.ClassifyUnknownHosts = false
	fc = newFlow(t, rt, "http://metrics.unknown.example/collect")
	fc.Request.Header.Set("Referer", "http://news.example/")
	fc.Policy = p
	addons.AdBlocker{Classifier: hostStub{ad: true}}.HandleRequest(fc)
	if fc.Response != nil {
		t.Fatal("classify_unknown_hosts=false must skip the model")
	}
}

func TestAdBlockerInjectsCosmeticCSS(t *testing.T) {
	rt := adRuntime(t)
	ab := addons.AdBlocker{}
	fc := newFlow(t, rt, "http://news.example/")
	fc.Policy = adPolicy()
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}}
	fc.ResponseBody = []byte(`<html><head><title>x</title></head><body><div id="AD_300"></div><div class="sidebar-promo"></div></body></html>`)
	ab.HandleResponse(fc)
	body := string(fc.ResponseBody)
	if !strings.Contains(body, `<style id="webfilter-adblock">`) || !strings.Contains(body, "#AD_300") || !strings.Contains(body, ".sidebar-promo") {
		t.Fatalf("expected injected css:\n%s", body)
	}
	if !strings.HasPrefix(body, "<html><head><style") {
		t.Fatalf("css must be injected right after <head>:\n%s", body[:60])
	}
	if fc.Response.Header.Get("Content-Length") == "" || fc.WFAction != "modified" {
		t.Fatalf("content-length/action not updated: %v %q", fc.Response.Header, fc.WFAction)
	}

	// Cosmetic off: untouched.
	fc = newFlow(t, rt, "http://news.example/")
	p := adPolicy()
	p.AdBlock.Cosmetic = false
	fc.Policy = p
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	fc.ResponseBody = []byte(`<html><head></head><body><div id="AD_300"></div></body></html>`)
	ab.HandleResponse(fc)
	if strings.Contains(string(fc.ResponseBody), "webfilter-adblock") {
		t.Fatal("cosmetic filtering disabled must not inject css")
	}
}
