package settingsvc

import (
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

func TestMergeSettingsPartialUpdate(t *testing.T) {
	cur := models.NewGlobalSettings()
	cur.LogRetentionDays = 14
	cur.UILanguage = "de"

	merged, err := MergeSettings(cur, []byte(`{"log_blocks": false}`))
	if err != nil {
		t.Fatalf("MergeSettings: %v", err)
	}
	if merged.LogBlocks {
		t.Error("log_blocks should have been updated to false")
	}
	if merged.LogRetentionDays != 14 {
		t.Errorf("log_retention_days clobbered: got %d, want 14", merged.LogRetentionDays)
	}
	if merged.UILanguage != "de" {
		t.Errorf("ui_language clobbered: got %q, want de", merged.UILanguage)
	}
}

func TestMergeSettingsProtectsSecretFields(t *testing.T) {
	cur := models.NewGlobalSettings()
	cur.PasswordHash = "orig-hash"
	cur.SecretKey = "orig-key"
	cur.ProxyAuthPasswordHash = "orig-proxy-hash"

	body := `{"password_hash":"evil","secret_key":"evil","proxy_auth_password_hash":"evil"}`
	merged, err := MergeSettings(cur, []byte(body))
	if err != nil {
		t.Fatalf("MergeSettings: %v", err)
	}
	if merged.PasswordHash != "orig-hash" || merged.SecretKey != "orig-key" || merged.ProxyAuthPasswordHash != "orig-proxy-hash" {
		t.Errorf("secret fields were writable directly: %+v", merged)
	}
}

func TestMergeSettingsNewPassword(t *testing.T) {
	cur := models.NewGlobalSettings()
	merged, err := MergeSettings(cur, []byte(`{"new_password":"hunter2","auth_enabled":true}`))
	if err != nil {
		t.Fatalf("MergeSettings: %v", err)
	}
	if !pwhash.Verify("hunter2", merged.PasswordHash) {
		t.Error("new_password was not hashed into password_hash")
	}
	if merged.SecretKey == "" {
		t.Error("secret_key was not generated alongside the first password")
	}
	if !merged.AuthEnabled {
		t.Error("auth_enabled not applied")
	}
}

func TestMergeSettingsAuthRequiresPassword(t *testing.T) {
	cur := models.NewGlobalSettings()
	_, err := MergeSettings(cur, []byte(`{"auth_enabled":true}`))
	if err == nil {
		t.Fatal("expected validation error enabling auth without a password")
	}
	if !IsValidationError(err) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "Set a password") {
		t.Errorf("unexpected message: %q", err.Error())
	}
}

func TestMergeSettingsInvalidBody(t *testing.T) {
	_, err := MergeSettings(models.NewGlobalSettings(), []byte(`{not json`))
	if err == nil || !IsValidationError(err) {
		t.Fatalf("expected ValidationError for malformed body, got %v", err)
	}
}

func TestSettingsDTORedaction(t *testing.T) {
	s := models.NewGlobalSettings()
	s.PasswordHash = "h"
	s.SecretKey = "k"
	s.ProxyAuthPasswordHash = "p"

	dto := SettingsDTO(s)
	for _, secret := range []string{"password_hash", "secret_key", "proxy_auth_password_hash"} {
		if _, ok := dto[secret]; ok {
			t.Errorf("%s leaked into DTO", secret)
		}
	}
	if dto["has_password"] != true || dto["has_proxy_auth"] != true {
		t.Errorf("derived booleans wrong: has_password=%v has_proxy_auth=%v", dto["has_password"], dto["has_proxy_auth"])
	}
}

func TestMergePolicyPatchPreservesSiblingFields(t *testing.T) {
	cur := models.NewPolicy()
	cur.Name = "default"
	cur.TextClassifier.Threshold = 0.95
	cur.TextClassifier.Exclude = []string{"example.com"}

	// The regression this package exists for: enabling a sub-config must not
	// reset its sibling fields to defaults via the sub-config's
	// reset-then-overlay UnmarshalJSON.
	p, err := MergePolicyPatch(cur, []byte(`{"text_classifier":{"enabled":true}}`))
	if err != nil {
		t.Fatalf("MergePolicyPatch: %v", err)
	}
	if !p.TextClassifier.Enabled {
		t.Error("enabled not applied")
	}
	if p.TextClassifier.Threshold != 0.95 {
		t.Errorf("threshold reset to %v, want 0.95", p.TextClassifier.Threshold)
	}
	if len(p.TextClassifier.Exclude) != 1 || p.TextClassifier.Exclude[0] != "example.com" {
		t.Errorf("exclude clobbered: %v", p.TextClassifier.Exclude)
	}
}

func TestMergePolicyPatchStringTypedThreshold(t *testing.T) {
	// Android restriction bundles have no float type; thresholds arrive as
	// strings and must round-trip through decodeJSONFloat.
	p, err := MergePolicyPatch(models.NewPolicy(), []byte(`{"image_classifier":{"threshold":"0.55"}}`))
	if err != nil {
		t.Fatalf("MergePolicyPatch: %v", err)
	}
	if p.ImageClassifier.Threshold != 0.55 {
		t.Errorf("threshold = %v, want 0.55", p.ImageClassifier.Threshold)
	}
}

func TestMergePolicyPatchArraysReplace(t *testing.T) {
	cur := models.NewPolicy()
	cur.UrlFilter.Block = []string{"old.example", "keep.example"}

	p, err := MergePolicyPatch(cur, []byte(`{"url_filter":{"block":["new.example"]}}`))
	if err != nil {
		t.Fatalf("MergePolicyPatch: %v", err)
	}
	if len(p.UrlFilter.Block) != 1 || p.UrlFilter.Block[0] != "new.example" {
		t.Errorf("arrays must replace, not append: %v", p.UrlFilter.Block)
	}
}

func TestMergePolicyPatchNestedEngines(t *testing.T) {
	cur := models.NewPolicy()
	cur.SafeSearch.Engines = map[string]models.SafeSearchEngineConfig{
		"google": {Enabled: true, BlockImagesTab: true},
		"bing":   {Enabled: true},
	}

	p, err := MergePolicyPatch(cur, []byte(`{"safesearch":{"engines":{"google":{"block_ai_tab":true}}}}`))
	if err != nil {
		t.Fatalf("MergePolicyPatch: %v", err)
	}
	g := p.SafeSearch.Engines["google"]
	if !g.BlockAiTab {
		t.Error("block_ai_tab not applied")
	}
	if !g.BlockImagesTab {
		t.Error("google.block_images_tab clobbered by nested merge")
	}
	if _, ok := p.SafeSearch.Engines["bing"]; !ok {
		t.Error("sibling engine bing dropped by nested merge")
	}
}

func TestMergePolicyPatchInvalidJSON(t *testing.T) {
	_, err := MergePolicyPatch(models.NewPolicy(), []byte(`{nope`))
	if err == nil || !IsValidationError(err) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
}

// A half-configured management TLS pair must be rejected at PUT time, not
// discovered at the next start - the operator is editing this through the
// very interface it would break.
func TestMergeSettingsRejectsHalfConfiguredMgmtTLS(t *testing.T) {
	cur := models.NewGlobalSettings()

	for _, body := range []string{
		`{"mgmt_tls":true,"mgmt_cert_file":"/tmp/only-cert.pem"}`,
		`{"mgmt_tls":true,"mgmt_key_file":"/tmp/only-key.pem"}`,
	} {
		if _, err := MergeSettings(cur, []byte(body)); err == nil {
			t.Errorf("%s was accepted; want a validation error", body)
		} else if !IsValidationError(err) {
			t.Errorf("%s gave %v; want a ValidationError (400, not 500)", body, err)
		}
	}
}

// An unreadable or mismatched pair must also fail validation rather than
// taking the management server down on the next restart.
func TestMergeSettingsRejectsUnloadableMgmtTLSPair(t *testing.T) {
	cur := models.NewGlobalSettings()
	body := `{"mgmt_tls":true,"mgmt_cert_file":"/nonexistent/cert.pem","mgmt_key_file":"/nonexistent/key.pem"}`

	if _, err := MergeSettings(cur, []byte(body)); err == nil {
		t.Error("a nonexistent certificate pair was accepted")
	} else if !IsValidationError(err) {
		t.Errorf("got %v; want a ValidationError", err)
	}
}

// mgmt_tls with no cert files is the supported "mint from the runtime CA"
// mode and must validate cleanly.
func TestMergeSettingsAllowsMgmtTLSWithoutCertFiles(t *testing.T) {
	cur := models.NewGlobalSettings()

	got, err := MergeSettings(cur, []byte(`{"mgmt_tls":true}`))
	if err != nil {
		t.Fatalf("mgmt_tls without cert files was rejected: %v", err)
	}
	if !got.MgmtTLS {
		t.Error("mgmt_tls did not survive the merge")
	}
}
