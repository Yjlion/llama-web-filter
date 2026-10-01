package addons_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// newFullRuntime builds a real *state.Runtime via state.New (CA, log
// store, policy store all backed by a temp dir) - needed here (unlike
// newTestRuntime elsewhere in this package) because PolicyRouter exercises
// the actual policies/*.json load path, not just Settings/Logs/Categories.
func newFullRuntime(t *testing.T) *state.Runtime {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
	}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed settings: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatalf("write seed settings: %v", err)
	}
	rt, err := state.New(settingsPath)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	t.Cleanup(func() { rt.Logs.Close() })
	return rt
}

func writePolicy(t *testing.T, rt *state.Runtime, p models.Policy) {
	t.Helper()
	dir := rt.Settings().PoliciesDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir policies dir: %v", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, p.Name+".json"), data, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	rt.ReloadPolicies()
}

func TestPolicyRouterAttachesMatchedPolicy(t *testing.T) {
	rt := newFullRuntime(t)
	p := models.NewPolicy()
	p.Name = "guest"
	p.SourceIPs = []string{"192.168.1.0/24"}
	writePolicy(t, rt, p)

	fc := newFlow(t, rt, "http://example.com/")
	fc.ClientIP = "192.168.1.77"

	addons.PolicyRouter{}.HandleRequest(fc)

	if fc.Policy == nil || fc.Policy.Name != "guest" {
		t.Fatalf("fc.Policy = %+v, want guest", fc.Policy)
	}
}

func TestPolicyRouterNoMatchLeavesPolicyNil(t *testing.T) {
	rt := newFullRuntime(t)
	p := models.NewPolicy()
	p.Name = "specific"
	p.SourceIPs = []string{"10.0.0.0/8"}
	writePolicy(t, rt, p)

	fc := newFlow(t, rt, "http://example.com/")
	fc.ClientIP = "203.0.113.5"

	addons.PolicyRouter{}.HandleRequest(fc)

	if fc.Policy != nil {
		t.Fatalf("fc.Policy = %+v, want nil", fc.Policy)
	}
}
