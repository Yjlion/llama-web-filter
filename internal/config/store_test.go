package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/models"
)

func TestLoadSettingsMissingFileReturnsDefaults(t *testing.T) {
	s, err := config.LoadSettings(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if s.MgmtPort != 8000 {
		t.Errorf("MgmtPort = %d, want default 8000", s.MgmtPort)
	}
}

func TestBootstrapRuntimeFilesCreatesMissingSettingsAndDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")
	if err := config.BootstrapRuntimeFiles(settingsPath); err != nil {
		t.Fatalf("BootstrapRuntimeFiles: %v", err)
	}
	if _, err := os.Stat(settingsPath); err != nil {
		t.Fatalf("settings not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join("policies", "default.json")); err == nil {
		t.Fatalf("bootstrap wrote default policy relative to cwd instead of settings")
	}
	if _, err := os.Stat(filepath.Join(dir, "policies", "default.json")); err != nil {
		t.Fatalf("default policy not created: %v", err)
	}
}

func TestBootstrapRuntimeFilesPreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	settings := models.NewGlobalSettings()
	settings.PoliciesDir = filepath.Join(dir, "policies")
	if err := config.SaveSettings(settingsPath, settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if err := os.MkdirAll(settings.PoliciesDir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	policyPath := filepath.Join(settings.PoliciesDir, "default.json")
	original := []byte(`{"name":"kept"}`)
	if err := os.WriteFile(policyPath, original, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := config.BootstrapRuntimeFiles(settingsPath); err != nil {
		t.Fatalf("BootstrapRuntimeFiles: %v", err)
	}
	got, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("policy overwritten: %s", got)
	}
}

func TestSaveThenLoadSettingsRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "settings.json")
	s := models.NewGlobalSettings()
	s.MgmtPort = 9001
	s.AuthEnabled = true

	if err := config.SaveSettings(path, s); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	loaded, err := config.LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if loaded.MgmtPort != 9001 || !loaded.AuthEnabled {
		t.Errorf("loaded = %+v, want MgmtPort=9001 AuthEnabled=true", loaded)
	}
}
