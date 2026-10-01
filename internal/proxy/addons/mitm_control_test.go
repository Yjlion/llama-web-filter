package addons_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func TestMitmControlIncludeModePassesNonListedSites(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://other.com/")
	policy := models.NewPolicy()
	policy.Mitm = models.MitmConfig{Mode: models.MitmModeInclude, Sites: []string{"example.com"}}
	fc.Policy = &policy

	addons.MitmControl{}.HandleRequest(fc)

	if !fc.MitmPassthrough {
		t.Error("expected passthrough for a site not in the include list")
	}
}

func TestMitmControlIncludeModeFiltersListedSites(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	policy := models.NewPolicy()
	policy.Mitm = models.MitmConfig{Mode: models.MitmModeInclude, Sites: []string{"example.com"}}
	fc.Policy = &policy

	addons.MitmControl{}.HandleRequest(fc)

	if fc.MitmPassthrough {
		t.Error("did not expect passthrough for a listed site under include mode")
	}
}

func TestMitmControlUserAgentExclude(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	fc.Request.Header.Set("User-Agent", "SomeApp/1.0 (special-device)")
	policy := models.NewPolicy()
	policy.Mitm = models.MitmConfig{UAMode: models.MitmUAModeExclude, UserAgents: []string{"special-device"}}
	fc.Policy = &policy

	addons.MitmControl{}.HandleRequest(fc)

	if !fc.MitmPassthrough {
		t.Error("expected passthrough for a UA matching an exclude rule")
	}
}

func TestMitmControlUserAgentInclude(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	fc.Request.Header.Set("User-Agent", "RegularBrowser/1.0")
	policy := models.NewPolicy()
	policy.Mitm = models.MitmConfig{UAMode: models.MitmUAModeInclude, UserAgents: []string{"special-device"}}
	fc.Policy = &policy

	addons.MitmControl{}.HandleRequest(fc)

	if !fc.MitmPassthrough {
		t.Error("expected passthrough for a UA NOT matching an include rule")
	}
}

func TestMitmControlNoPolicyIsNoop(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	addons.MitmControl{}.HandleRequest(fc)
	if fc.MitmPassthrough {
		t.Error("expected no passthrough with no policy attached")
	}
}
