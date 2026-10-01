package addons_test

import (
	"net/http"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func TestManagementAccessPseudoDomainRedirect(t *testing.T) {
	rt := newTestRuntime(t)
	cfg := *rt.Settings()
	cfg.MgmtHostname = "web.filter"
	cfg.MgmtPort = 8000
	rt.SetSettings(cfg)
	fc := newFlow(t, rt, "http://web.filter/")
	fc.ProxySockName = "192.168.1.1"

	addons.ManagementAccess{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected a redirect response")
	}
	if fc.Response.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302", fc.Response.StatusCode)
	}
	if loc := fc.Response.Header.Get("Location"); loc != "http://192.168.1.1:8000/" {
		t.Errorf("Location = %q, want http://192.168.1.1:8000/", loc)
	}
	if !fc.URLAllowed || !fc.MitmPassthrough {
		t.Error("expected URLAllowed and MitmPassthrough to be set")
	}
}

func TestManagementAccessPassthroughForLocalMgmtPort(t *testing.T) {
	rt := newTestRuntime(t)
	cfg := *rt.Settings()
	cfg.MgmtHostname = "web.filter"
	cfg.MgmtPort = 8000
	rt.SetSettings(cfg)
	fc := newFlow(t, rt, "http://127.0.0.1:8000/api/status")

	addons.ManagementAccess{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Error("did not expect a response - passthrough should just set flags")
	}
	if !fc.URLAllowed || !fc.MitmPassthrough {
		t.Error("expected URLAllowed and MitmPassthrough for loopback management-port traffic")
	}
}

func TestManagementAccessIgnoresUnrelatedTraffic(t *testing.T) {
	rt := newTestRuntime(t)
	cfg := *rt.Settings()
	cfg.MgmtHostname = "web.filter"
	cfg.MgmtPort = 8000
	rt.SetSettings(cfg)
	fc := newFlow(t, rt, "http://example.com/")

	addons.ManagementAccess{}.HandleRequest(fc)

	if fc.Response != nil || fc.URLAllowed || fc.MitmPassthrough {
		t.Error("did not expect any management-access effect on unrelated traffic")
	}
}

func TestManagementAccessNonLocalMgmtPortNotPassedThrough(t *testing.T) {
	rt := newTestRuntime(t)
	cfg := *rt.Settings()
	cfg.MgmtHostname = "web.filter"
	cfg.MgmtPort = 8000
	rt.SetSettings(cfg)
	// Same port as management, but not a local/loopback destination and not
	// the proxy's own sockname - must NOT be granted passthrough.
	fc := newFlow(t, rt, "http://8.8.8.8:8000/")

	addons.ManagementAccess{}.HandleRequest(fc)

	if fc.URLAllowed || fc.MitmPassthrough {
		t.Error("did not expect passthrough for a non-local destination on the mgmt port")
	}
}
