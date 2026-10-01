package addons_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

func TestRequestLoggerHandleResponseSetsWFLogged(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	policy := models.NewPolicy()
	policy.Name = "default"
	fc.Policy = &policy

	addons.RequestLogger{}.HandleResponse(fc)

	if !fc.WFLogged {
		t.Error("expected WFLogged to be set after HandleResponse")
	}
}

func TestRequestLoggerHandleErrorSkipsIfAlreadyLogged(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	fc.WFLogged = true

	// Should not panic or attempt to log twice; nothing to assert on the
	// store directly, so this just guards the dedup branch executes.
	addons.RequestLogger{}.HandleError(fc)
}

func TestRequestLoggerHandleErrorLogsWhenNotYetLogged(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")

	addons.RequestLogger{}.HandleError(fc)

	if !fc.WFLogged {
		t.Error("expected WFLogged to be set after HandleError")
	}
}
