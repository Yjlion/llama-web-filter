package models_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}

// TestSettingsRoundTrip validates that the actual settings.json files from
// the Python original (config/settings.json and settings.example.json,
// copied into testdata/) unmarshal into GlobalSettings and that
// marshal->unmarshal is idempotent - the core "existing config directories
// work with the new binary" requirement.
func TestSettingsRoundTrip(t *testing.T) {
	for _, name := range []string{"settings.json", "settings.example.json"} {
		t.Run(name, func(t *testing.T) {
			data := readTestdata(t, name)

			var s1 models.GlobalSettings
			if err := json.Unmarshal(data, &s1); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			remarshaled, err := json.Marshal(s1)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var s2 models.GlobalSettings
			if err := json.Unmarshal(remarshaled, &s2); err != nil {
				t.Fatalf("unmarshal round-trip: %v", err)
			}
			if !reflect.DeepEqual(s1, s2) {
				t.Fatalf("round-trip mismatch:\n  first:  %+v\n  second: %+v", s1, s2)
			}
		})
	}
}

func TestSettingsRealFileFieldValues(t *testing.T) {
	data := readTestdata(t, "settings.json")
	var s models.GlobalSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.MgmtPort != 8000 {
		t.Errorf("MgmtPort = %d, want 8000", s.MgmtPort)
	}
	if len(s.ProxyListen) != 1 || s.ProxyListen[0] != "0.0.0.0:8080" {
		t.Errorf("ProxyListen = %v, want [0.0.0.0:8080]", s.ProxyListen)
	}
	if s.MgmtHostname != "web.filter" {
		t.Errorf("MgmtHostname = %q, want web.filter", s.MgmtHostname)
	}
	if s.LogRetentionDays != 30 {
		t.Errorf("LogRetentionDays = %d, want 30", s.LogRetentionDays)
	}
	if s.DBPath() != filepath.Join("./logs", "webfilter.db") {
		t.Errorf("DBPath() = %q", s.DBPath())
	}
	if s.PrimaryProxyPort() != 8080 {
		t.Errorf("PrimaryProxyPort() = %d, want 8080", s.PrimaryProxyPort())
	}
}

// TestSettingsExampleAppliesDefaultsForMissingFields checks that fields
// absent from settings.example.json (a deliberately minimal file -
// categories_dir, pac_proxy_host, pac_direct_hosts, upstream_*,
// proxy_auth_*) still take their documented Python defaults.
func TestSettingsExampleAppliesDefaultsForMissingFields(t *testing.T) {
	data := readTestdata(t, "settings.example.json")
	var s models.GlobalSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.CategoriesDir != "./categories" {
		t.Errorf("CategoriesDir = %q, want ./categories (default)", s.CategoriesDir)
	}
	if s.PacProxyHost != "" {
		t.Errorf("PacProxyHost = %q, want empty default", s.PacProxyHost)
	}
	if s.PacDirectHosts == nil || len(s.PacDirectHosts) != 0 {
		t.Errorf("PacDirectHosts = %v, want empty non-nil slice", s.PacDirectHosts)
	}
	if s.ProxyAuthEnabled {
		t.Errorf("ProxyAuthEnabled = true, want default false")
	}
}

// TestPolicyRoundTrip validates the two real policy fixtures from the
// Python original.
func TestPolicyRoundTrip(t *testing.T) {
	for _, name := range []string{"default.json", "default-copy.json"} {
		t.Run(name, func(t *testing.T) {
			data := readTestdata(t, name)

			var p1 models.Policy
			if err := json.Unmarshal(data, &p1); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			remarshaled, err := json.Marshal(p1)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var p2 models.Policy
			if err := json.Unmarshal(remarshaled, &p2); err != nil {
				t.Fatalf("unmarshal round-trip: %v", err)
			}
			if !reflect.DeepEqual(p1, p2) {
				t.Fatalf("round-trip mismatch:\n  first:  %+v\n  second: %+v", p1, p2)
			}
		})
	}
}

// TestPolicyRealFileFieldValues spot-checks known values from the real
// default.json fixture, including defaults applied for fields the file
// omits entirely (schedule, source_macs, mitm.ua_mode/user_agents).
func TestPolicyRealFileFieldValues(t *testing.T) {
	data := readTestdata(t, "default.json")
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Name != "default" {
		t.Errorf("Name = %q, want default", p.Name)
	}
	if len(p.Mitm.Sites) != 1 || p.Mitm.Sites[0] != "chase.com" {
		t.Errorf("Mitm.Sites = %v, want [chase.com]", p.Mitm.Sites)
	}
	if p.ImageClassifier.Threshold != 0.75 {
		t.Errorf("ImageClassifier.Threshold = %v, want 0.75 (file override, not the 0.4 default)", p.ImageClassifier.Threshold)
	}
	// Fields entirely absent from the file must still get Python defaults.
	if p.Schedule.Enabled {
		t.Errorf("Schedule.Enabled = true, want default false")
	}
	if p.SourceMACs == nil || len(p.SourceMACs) != 0 {
		t.Errorf("SourceMACs = %v, want empty non-nil slice default", p.SourceMACs)
	}
	if p.Mitm.UAMode != models.MitmUAModeOff {
		t.Errorf("Mitm.UAMode = %q, want off (default)", p.Mitm.UAMode)
	}
	if p.YouTube.BlockHome != true {
		t.Errorf("YouTube.BlockHome = %v, want true (default)", p.YouTube.BlockHome)
	}
}

// TestPolicyLegacySafeSearchMigration validates the legacy flat-schema
// migration against the *real* default-copy.json fixture, which - as
// shipped by the Python original - still uses the pre-engines-map flat
// safesearch schema (top-level block_images_tab/block_videos_tab/
// block_ai_tab, no "engines" key). This is real ground truth, not a
// synthetic example.
func TestPolicyLegacySafeSearchMigration(t *testing.T) {
	data := readTestdata(t, "default-copy.json")
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.SafeSearch.Engines) != len(models.SafeSearchEngines) {
		t.Fatalf("Engines has %d entries, want %d (one per known engine)",
			len(p.SafeSearch.Engines), len(models.SafeSearchEngines))
	}
	for _, name := range models.SafeSearchEngines {
		eng, ok := p.SafeSearch.Engines[name]
		if !ok {
			t.Fatalf("Engines missing entry for %q", name)
		}
		if !eng.Enabled {
			t.Errorf("Engines[%q].Enabled = false, want true (migrated default)", name)
		}
		if eng.BlockImagesTab || eng.BlockVideosTab || eng.BlockAiTab {
			t.Errorf("Engines[%q] block flags = %+v, want all false (matches file's legacy flags)", name, eng)
		}
	}
}

// TestPolicySafeSearchLegacyMigrationWithFlagsSet uses a hand-crafted
// fixture (the real files above all have every legacy flag false, which
// wouldn't catch a bug in the *value* propagation) to confirm true legacy
// flag values actually carry over into every engine.
func TestPolicySafeSearchLegacyMigrationWithFlagsSet(t *testing.T) {
	data := []byte(`{
		"name": "legacy-test",
		"safesearch": {
			"enabled": true,
			"block_images_tab": true,
			"block_videos_tab": false,
			"block_ai_tab": true,
			"exclude": [],
			"include_only": []
		}
	}`)
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, name := range models.SafeSearchEngines {
		eng := p.SafeSearch.Engines[name]
		if !eng.BlockImagesTab || eng.BlockVideosTab != false || !eng.BlockAiTab {
			t.Errorf("Engines[%q] = %+v, want BlockImagesTab=true BlockVideosTab=false BlockAiTab=true", name, eng)
		}
	}
}

// TestPolicySafeSearchEnginesMapNotOverriddenByLegacyMigration ensures a
// policy that already uses the new engines-map schema is left untouched -
// the legacy migration must only fire when "engines" is entirely absent.
func TestPolicySafeSearchEnginesMapNotOverriddenByLegacyMigration(t *testing.T) {
	data := []byte(`{
		"name": "modern-test",
		"safesearch": {
			"enabled": true,
			"engines": {
				"google": {"enabled": true, "block_images_tab": true, "block_videos_tab": false, "block_ai_tab": false}
			},
			"block_images_tab": false,
			"exclude": [],
			"include_only": []
		}
	}`)
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.SafeSearch.Engines) != 1 {
		t.Fatalf("Engines = %+v, want exactly the 1 explicit entry (no legacy migration should fire)", p.SafeSearch.Engines)
	}
	if !p.SafeSearch.Engines["google"].BlockImagesTab {
		t.Errorf("Engines[google].BlockImagesTab = false, want true (from explicit engines map)")
	}
}

func TestPolicySourceMACsNormalization(t *testing.T) {
	data := []byte(`{"name": "t", "source_macs": ["AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "not-a-mac", "11:22:33:44:55:66"]}`)
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
	if !reflect.DeepEqual(p.SourceMACs, want) {
		t.Errorf("SourceMACs = %v, want %v", p.SourceMACs, want)
	}
}

func TestPolicyClassifierNumericStrings(t *testing.T) {
	data := []byte(`{
		"name": "browser-payload",
		"text_classifier": {"enabled": true, "threshold": "0.55", "exclude": [], "include_only": []},
		"image_classifier": {"enabled": true, "action": "blur", "threshold": "0.45", "min_dimension": "128", "exclude": [], "include_only": []}
	}`)
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.TextClassifier.Threshold != 0.55 {
		t.Errorf("TextClassifier.Threshold = %v, want 0.55", p.TextClassifier.Threshold)
	}
	if p.ImageClassifier.Threshold != 0.45 {
		t.Errorf("ImageClassifier.Threshold = %v, want 0.45", p.ImageClassifier.Threshold)
	}
	if p.ImageClassifier.MinDimension != 128 {
		t.Errorf("ImageClassifier.MinDimension = %v, want 128", p.ImageClassifier.MinDimension)
	}
}

func TestSettingsLegacyProxyPortMigration(t *testing.T) {
	data := []byte(`{"proxy_port": 9090, "listen_host": "127.0.0.1"}`)
	var s models.GlobalSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.ProxyListen) != 1 || s.ProxyListen[0] != "127.0.0.1:9090" {
		t.Errorf("ProxyListen = %v, want [127.0.0.1:9090]", s.ProxyListen)
	}
	if s.MgmtHost != "127.0.0.1" {
		t.Errorf("MgmtHost = %q, want 127.0.0.1", s.MgmtHost)
	}
}
