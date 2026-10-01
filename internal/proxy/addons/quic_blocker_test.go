package addons_test

import (
	"net/http"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func TestQuicBlockerStripsAltSvcWhenEnabled(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	policy := models.NewPolicy()
	policy.UrlFilter.BlockQuic = true
	fc.Policy = &policy
	fc.Response = &http.Response{Header: http.Header{"Alt-Svc": []string{`h3=":443"`}}}

	addons.QuicBlocker{}.HandleResponse(fc)

	if fc.Response.Header.Get("Alt-Svc") != "" {
		t.Error("expected Alt-Svc header to be stripped")
	}
}

func TestQuicBlockerLeavesHeaderWhenDisabled(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	policy := models.NewPolicy()
	policy.UrlFilter.BlockQuic = false
	fc.Policy = &policy
	fc.Response = &http.Response{Header: http.Header{"Alt-Svc": []string{`h3=":443"`}}}

	addons.QuicBlocker{}.HandleResponse(fc)

	if fc.Response.Header.Get("Alt-Svc") == "" {
		t.Error("did not expect Alt-Svc to be stripped when block_quic is off")
	}
}
