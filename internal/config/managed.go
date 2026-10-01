package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ManagedState records that the device's configuration is provisioned by an
// external manager (an MDM/EMM portal via Android managed configurations).
// It lives in its own file - managed.json beside settings.json - rather
// than inside GlobalSettings because settings.json is loaded once at
// startup and is writable through PUT /api/settings; the lock must be
// re-checked per request and must not be reachable through the very API it
// gates. Desktop builds never write this file; a missing file means
// "not managed", so desktop behavior is unchanged.
type ManagedState struct {
	Managed        bool `json:"managed"`
	SettingsLocked bool `json:"settings_locked"`
	// RestrictionsHash is the sha256 of the canonical applied restrictions
	// document, used to short-circuit re-application (the mgmt password
	// restriction would otherwise be re-hashed with a fresh salt on every
	// boot, rewriting settings.json and invalidating sessions each time).
	RestrictionsHash string `json:"restrictions_hash"`
	AppliedAt        string `json:"applied_at"`
}

// ManagedStatePath returns the managed.json path for a given settings.json
// path (always a sibling file).
func ManagedStatePath(settingsPath string) string {
	return filepath.Join(filepath.Dir(settingsPath), "managed.json")
}

// LoadManagedState reads managed.json. A missing file is the normal
// unmanaged state: zero value, nil error.
func LoadManagedState(settingsPath string) (ManagedState, error) {
	data, err := os.ReadFile(ManagedStatePath(settingsPath))
	if os.IsNotExist(err) {
		return ManagedState{}, nil
	}
	if err != nil {
		return ManagedState{}, fmt.Errorf("read managed state: %w", err)
	}
	var st ManagedState
	if err := json.Unmarshal(data, &st); err != nil {
		return ManagedState{}, fmt.Errorf("parse managed state: %w", err)
	}
	return st, nil
}

// SaveManagedState writes managed.json atomically.
func SaveManagedState(settingsPath string, st ManagedState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal managed state: %w", err)
	}
	return atomicWriteFile(ManagedStatePath(settingsPath), data)
}

// ClearManagedState removes managed.json (device un-enrolled). Removing a
// file that doesn't exist is not an error.
func ClearManagedState(settingsPath string) error {
	err := os.Remove(ManagedStatePath(settingsPath))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear managed state: %w", err)
	}
	return nil
}
