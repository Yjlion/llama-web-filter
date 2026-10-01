package settingsvc

import (
	"reflect"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// Every field must be deliberately classified. When someone adds a field to
// GlobalSettings, this fails unless they either list it in hotFields or
// record here that restart-required is the intended answer - which is the
// whole point of defaulting to restart-required rather than guessing.
func TestEverySettingsFieldIsClassified(t *testing.T) {
	// Fields intentionally treated as restart-required. Keeping them listed
	// (rather than just "anything not hot") is what makes an unclassified
	// new field stand out.
	restartRequired := map[string]bool{
		"proxy_listen":       true,
		"mgmt_host":          true,
		"mgmt_port":          true,
		"mgmt_tls":           true,
		"mgmt_cert_file":     true,
		"mgmt_key_file":      true,
		"cert_dir":           true,
		"policies_dir":       true,
		"logs_dir":           true,
		"log_blocks":         true,
		"log_requests":       true,
		"log_retention_days": true,
		"upstream_proxy":     true,
		"upstream_auth":      true,
		"disable_tray":       true,
		"llm":                true,
	}

	for _, name := range SettingsFieldNames() {
		hot := hotFields[name]
		cold := restartRequired[name]
		switch {
		case hot && cold:
			t.Errorf("field %q is listed as both hot and restart-required", name)
		case !hot && !cold:
			t.Errorf("field %q is unclassified: add it to hotFields (every consumer "+
				"reads it per request) or to restartRequired in this test", name)
		}
	}
}

func TestDiffSettingsReportsChangedFields(t *testing.T) {
	old := models.NewGlobalSettings()
	next := old
	next.UILanguage = "de"
	next.MgmtPort = 9999

	got := DiffSettings(old, next)
	want := []Change{
		{Field: "mgmt_port", Hot: false},
		{Field: "ui_language", Hot: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DiffSettings() = %+v, want %+v", got, want)
	}
}

func TestDiffSettingsIgnoresUnchanged(t *testing.T) {
	s := models.NewGlobalSettings()
	if got := DiffSettings(s, s); len(got) != 0 {
		t.Errorf("DiffSettings(s, s) = %+v, want empty", got)
	}
}

// Slices and nested configs must compare by value, not by identity.
func TestDiffSettingsComparesCompositeValues(t *testing.T) {
	old := models.NewGlobalSettings()

	same := old
	same.ProxyListen = append([]string{}, old.ProxyListen...)
	if got := DiffSettings(old, same); len(got) != 0 {
		t.Errorf("equal-valued slice reported as changed: %+v", got)
	}

	changed := old
	changed.ProxyListen = []string{"0.0.0.0:9090"}
	if got := RestartRequired(old, changed); len(got) != 1 || got[0] != "proxy_listen" {
		t.Errorf("RestartRequired = %v, want [proxy_listen]", got)
	}

	nested := old
	nested.Icap.PreviewSize = 1234
	if got := DiffSettings(old, nested); len(got) != 1 || got[0].Field != "icap" || !got[0].Hot {
		t.Errorf("nested icap change = %+v, want one hot 'icap' change", got)
	}
}

func TestRestartRequiredOnlyListsColdFields(t *testing.T) {
	old := models.NewGlobalSettings()
	next := old
	next.UILanguage = "fr"       // hot
	next.ProxyAuthEnabled = true // hot
	next.LogsDir = "/var/log/wf" // cold
	next.LogRetentionDays = 7    // cold

	got := RestartRequired(old, next)
	want := []string{"log_retention_days", "logs_dir"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RestartRequired = %v, want %v", got, want)
	}
}

// RestartRequired must return an empty slice rather than nil, so the API
// serialises it as [] and the UI can test its length without a null check.
func TestRestartRequiredIsNeverNil(t *testing.T) {
	s := models.NewGlobalSettings()
	got := RestartRequired(s, s)
	if got == nil {
		t.Error("RestartRequired returned nil; want an empty slice (serialises as [], not null)")
	}
	if len(got) != 0 {
		t.Errorf("RestartRequired = %v, want empty", got)
	}
}

// The core safety property: hot fields move, restart-required fields keep
// the value that is actually in effect.
func TestMergeHotTakesOnlyHotFields(t *testing.T) {
	live := models.NewGlobalSettings()
	live.MgmtPort = 8000
	live.UILanguage = "en"
	live.ProxyListen = []string{"0.0.0.0:8080"}

	next := live
	next.MgmtPort = 9999                        // cold: must NOT move
	next.ProxyListen = []string{"0.0.0.0:9090"} // cold: must NOT move
	next.UILanguage = "de"                      // hot: must move
	next.ProxyAuthEnabled = true                // hot: must move
	next.Icap.PreviewSize = 2048                // hot: must move

	got := MergeHot(live, next)

	if got.MgmtPort != 8000 {
		t.Errorf("mgmt_port = %d, want 8000 (the bound port; a live reader must "+
			"never see a port nothing is listening on)", got.MgmtPort)
	}
	if !reflect.DeepEqual(got.ProxyListen, []string{"0.0.0.0:8080"}) {
		t.Errorf("proxy_listen = %v, want the bound listeners", got.ProxyListen)
	}
	if got.UILanguage != "de" {
		t.Errorf("ui_language = %q, want %q", got.UILanguage, "de")
	}
	if !got.ProxyAuthEnabled {
		t.Error("proxy_auth_enabled did not take effect")
	}
	if got.Icap.PreviewSize != 2048 {
		t.Errorf("icap.preview_size = %d, want 2048", got.Icap.PreviewSize)
	}
}

// Secrets are hot (mgmtapi reads them per request), so a password change
// must reach the live snapshot without a restart.
func TestMergeHotCarriesAuthChanges(t *testing.T) {
	live := models.NewGlobalSettings()
	next := live
	next.AuthEnabled = true
	next.PasswordHash = "pbkdf2_sha256$200000$aa$bb"
	next.SecretKey = "newsecret"

	got := MergeHot(live, next)
	if !got.AuthEnabled || got.PasswordHash == "" || got.SecretKey != "newsecret" {
		t.Errorf("auth fields did not survive MergeHot: %+v", got)
	}
}

func TestMergeHotIsIdentityWhenNothingHotChanged(t *testing.T) {
	live := models.NewGlobalSettings()
	next := live
	next.MgmtPort = 9999
	next.LogsDir = "/elsewhere"

	got := MergeHot(live, next)
	if !reflect.DeepEqual(got, live) {
		t.Errorf("MergeHot changed a snapshot when only cold fields differed:\n got: %+v\nwant: %+v", got, live)
	}
}
