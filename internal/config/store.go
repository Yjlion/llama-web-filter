// Package config loads and persists config/settings.json and
// policies/*.json - the filesystem is the only interface between the proxy
// engine and the management API, exactly as in the Python original, so
// this package is deliberately the single place both sides read/write
// through.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// BootstrapRuntimeFiles creates a usable first-run settings.json and
// policies/default.json if they are missing. It never overwrites existing
// files, so packaged examples and live runtime state remain user-owned.
func BootstrapRuntimeFiles(settingsPath string) error {
	if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
		settings := NewBootstrapSettings(settingsPath)
		if err := SaveSettings(settingsPath, settings); err != nil {
			return fmt.Errorf("bootstrap settings: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("stat settings: %w", err)
	}

	settings, err := LoadSettings(settingsPath)
	if err != nil {
		return err
	}
	defaultPolicyPath := filepath.Join(settings.PoliciesDir, "default.json")
	if _, err := os.Stat(defaultPolicyPath); os.IsNotExist(err) {
		p := models.NewPolicy()
		p.Name = "default"
		if err := (&PolicyStore{Dir: settings.PoliciesDir}).write(defaultPolicyPath, p); err != nil {
			return fmt.Errorf("bootstrap default policy: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("stat default policy: %w", err)
	}
	return nil
}

func NewBootstrapSettings(settingsPath string) models.GlobalSettings {
	settings := models.NewGlobalSettings()
	root := filepath.Dir(settingsPath)
	if filepath.Base(root) == "config" {
		root = filepath.Dir(root)
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	settings.CertDir = filepath.Join(root, "certs")
	settings.PoliciesDir = filepath.Join(root, "policies")
	settings.CategoriesDir = filepath.Join(root, "categories")
	settings.LogsDir = filepath.Join(root, "logs")
	settings.LLM.DataDir = filepath.Join(root, "data", "llm")
	settings.AdBlockDir = filepath.Join(root, "data", "adblock")
	return settings
}

// LoadSettings reads and parses settings.json. If the file doesn't exist,
// returns NewGlobalSettings() (documented defaults) with no error - the
// Python original's settings.example.json is copied by hand or the
// Settings page's first save creates it; a missing file is a valid empty
// starting state, not an error.
func LoadSettings(path string) (models.GlobalSettings, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return models.NewGlobalSettings(), nil
	}
	if err != nil {
		return models.GlobalSettings{}, fmt.Errorf("read settings: %w", err)
	}
	var s models.GlobalSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return models.GlobalSettings{}, fmt.Errorf("parse settings %s: %w", path, err)
	}
	return s, nil
}

// SaveSettings writes settings.json atomically (write to a temp file in the
// same directory, then rename) so a crash mid-write never leaves a
// truncated/corrupt config file for the other process to read.
func SaveSettings(path string, s models.GlobalSettings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return atomicWriteFile(path, data)
}

// atomicWriteFile writes data to a temp file beside path, then renames it
// into place. os.Rename is atomic on both Windows and POSIX when source
// and destination are on the same volume, which they always are here since
// the temp file is created in path's own directory.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
