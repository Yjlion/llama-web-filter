package addons_test

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// newTestRuntime builds a minimal *state.Runtime backed by a temp-dir
// logstore/category store, without going through state.New (which needs a
// full settings.json + CA on disk) - addon-level tests only care about
// Settings/Logs/Categories being usable.
func newTestRuntime(t *testing.T) *state.Runtime {
	t.Helper()
	dir := t.TempDir()
	logs, err := logstore.Configure(filepath.Join(dir, "webfilter.db"), 30, true, true)
	if err != nil {
		t.Fatalf("logstore.Configure: %v", err)
	}
	t.Cleanup(func() { logs.Close() })
	rt := &state.Runtime{Logs: logs}
	rt.SetSettings(models.NewGlobalSettings())
	return rt
}

func newFlow(t *testing.T, rt *state.Runtime, rawURL string) *proxy.FlowContext {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   u.Host,
		Header: http.Header{},
	}
	return &proxy.FlowContext{
		Runtime:  rt,
		ClientIP: "192.168.1.50",
		Request:  req,
	}
}
