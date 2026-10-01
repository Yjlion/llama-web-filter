package settingsvc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/config"
)

// newManagedFixture bootstraps a settings.json + default policy in a temp
// dir with absolute paths (the documented relative defaults resolve against
// the test process's working directory, not the settings file's location).
func newManagedFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	if err := config.BootstrapRuntimeFiles(settingsPath); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return settingsPath
}

func TestApplyManagedConfigTypedMergeDoesNotClobber(t *testing.T) {
	settingsPath := newManagedFixture(t)
	settings, _ := config.LoadSettings(settingsPath)
	store := config.NewPolicyStore(settings.PoliciesDir)

	// Simulate a prior user edit the EMM does not manage.
	p, _ := store.Get("default")
	p.TextClassifier.Threshold = 0.95
	p.YouTube.Channels = []string{"UCuserpick"}
	if err := store.Update("default", p); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	doc := `{"settings_locked":true,"policy":{"text_classifier":{"enabled":true},"safesearch":{"enabled":true}}}`
	res, err := ApplyManagedConfig(settingsPath, []byte(doc))
	if err != nil {
		t.Fatalf("ApplyManagedConfig: %v", err)
	}
	if !res.Changed || !res.PolicyChanged {
		t.Fatalf("expected Changed+PolicyChanged, got %+v", res)
	}

	got, _ := store.Get("default")
	if !got.TextClassifier.Enabled || !got.SafeSearch.Enabled {
		t.Error("managed keys not applied")
	}
	if got.TextClassifier.Threshold != 0.95 {
		t.Errorf("unmanaged threshold clobbered: %v", got.TextClassifier.Threshold)
	}
	if len(got.YouTube.Channels) != 1 || got.YouTube.Channels[0] != "UCuserpick" {
		t.Errorf("unmanaged youtube channels clobbered: %v", got.YouTube.Channels)
	}

	st, _ := config.LoadManagedState(settingsPath)
	if !st.Managed || !st.SettingsLocked || st.RestrictionsHash == "" {
		t.Errorf("managed state not recorded: %+v", st)
	}
}

func TestApplyManagedConfigPolicyJSONOverridesEverything(t *testing.T) {
	settingsPath := newManagedFixture(t)
	settings, _ := config.LoadSettings(settingsPath)
	store := config.NewPolicyStore(settings.PoliciesDir)

	p, _ := store.Get("default")
	p.UrlFilter.Block = []string{"user.example"}
	if err := store.Update("default", p); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	doc := `{"policy_json":"{\"name\":\"corp\",\"url_filter\":{\"enabled\":true,\"block\":[\"bad.example\"]}}","policy":{"doh":{"enabled":true}}}`
	res, err := ApplyManagedConfig(settingsPath, []byte(doc))
	if err != nil {
		t.Fatalf("ApplyManagedConfig: %v", err)
	}
	if !res.PolicyChanged {
		t.Fatal("expected PolicyChanged")
	}

	got, err := store.Get("default")
	if err != nil {
		t.Fatalf("default policy gone after policy_json override: %v", err)
	}
	if got.Name != "default" {
		t.Errorf("policy_json name must be forced to default, got %q", got.Name)
	}
	if !got.UrlFilter.Enabled || len(got.UrlFilter.Block) != 1 || got.UrlFilter.Block[0] != "bad.example" {
		t.Errorf("policy_json content not applied: %+v", got.UrlFilter)
	}
	if got.Doh.Enabled {
		t.Error("policy fragment must be ignored when policy_json is set")
	}
}

func TestApplyManagedConfigHashShortCircuit(t *testing.T) {
	settingsPath := newManagedFixture(t)

	doc := `{"settings_locked":true,"settings":{"log_retention_days":7,"new_password":"emm-secret","auth_enabled":true}}`
	res, err := ApplyManagedConfig(settingsPath, []byte(doc))
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if !res.Changed || !res.SettingsChanged {
		t.Fatalf("first apply should change settings, got %+v", res)
	}
	firstSettings, _ := os.ReadFile(settingsPath)

	// Re-applying the identical doc (even with different key order /
	// whitespace) must be a no-op: no scrypt re-hash, no file rewrite.
	reordered := `{ "settings": {"auth_enabled":true, "new_password":"emm-secret", "log_retention_days":7}, "settings_locked": true }`
	res2, err := ApplyManagedConfig(settingsPath, []byte(reordered))
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if res2.Changed {
		t.Error("identical doc must short-circuit (Changed=false)")
	}
	secondSettings, _ := os.ReadFile(settingsPath)
	if string(firstSettings) != string(secondSettings) {
		t.Error("settings.json rewritten on identical re-apply (scrypt churn)")
	}
}

func TestApplyManagedConfigEmptyDocClearsState(t *testing.T) {
	settingsPath := newManagedFixture(t)

	if _, err := ApplyManagedConfig(settingsPath, []byte(`{"settings_locked":true,"settings":{"log_blocks":false}}`)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	res, err := ApplyManagedConfig(settingsPath, []byte(`{}`))
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if !res.Changed {
		t.Error("clearing an enrolled device should report Changed")
	}
	st, _ := config.LoadManagedState(settingsPath)
	if st.Managed || st.SettingsLocked {
		t.Errorf("managed state not cleared: %+v", st)
	}
	// Applied values stay (un-enrolling doesn't revert), they just unlock.
	settings, _ := config.LoadSettings(settingsPath)
	if settings.LogBlocks {
		t.Error("previously applied setting should persist after un-enroll")
	}

	// Clearing again is a no-op.
	res2, err := ApplyManagedConfig(settingsPath, []byte(``))
	if err != nil {
		t.Fatalf("second clear: %v", err)
	}
	if res2.Changed {
		t.Error("clearing an unmanaged device must report Changed=false")
	}
}

func TestApplyManagedConfigValidationFailureIsAtomic(t *testing.T) {
	settingsPath := newManagedFixture(t)
	settings, _ := config.LoadSettings(settingsPath)
	store := config.NewPolicyStore(settings.PoliciesDir)
	beforePolicy, _ := store.Get("default")
	beforeSettings, _ := os.ReadFile(settingsPath)

	// auth_enabled without a password fails settings validation; the valid
	// policy fragment must NOT have been written either.
	doc := `{"settings":{"auth_enabled":true},"policy":{"doh":{"enabled":true}}}`
	_, err := ApplyManagedConfig(settingsPath, []byte(doc))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !IsValidationError(err) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}

	afterSettings, _ := os.ReadFile(settingsPath)
	if string(beforeSettings) != string(afterSettings) {
		t.Error("settings.json modified despite validation failure")
	}
	afterPolicy, _ := store.Get("default")
	if afterPolicy.Doh.Enabled != beforePolicy.Doh.Enabled {
		t.Error("policy modified despite settings validation failure (half-apply)")
	}
	st, _ := config.LoadManagedState(settingsPath)
	if st.Managed {
		t.Error("managed state recorded despite validation failure")
	}
}
