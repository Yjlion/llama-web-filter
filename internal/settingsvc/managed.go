package settingsvc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// ManagedDoc is the canonical managed-configuration document the Android
// layer builds from the EMM's RestrictionsManager bundle. Only keys the EMM
// actually set are present, so re-application never clobbers user edits to
// unmanaged fields.
type ManagedDoc struct {
	SettingsLocked bool `json:"settings_locked"`
	// PolicyJSON, when non-empty, is a full models.Policy document that
	// replaces the default policy wholesale (wins over Policy below).
	PolicyJSON string `json:"policy_json"`
	// Settings is a partial GlobalSettings body (MergeSettings semantics,
	// including new_password).
	Settings json.RawMessage `json:"settings"`
	// Policy is a JSON-merge-patch applied to the default policy.
	Policy json.RawMessage `json:"policy"`
}

// ApplyResult reports what ApplyManagedConfig actually did, so the caller
// (the gomobile wrapper) can refresh in-memory caches and decide whether an
// engine restart is needed.
type ApplyResult struct {
	// Changed is false when the document hash matched the previously applied
	// one (nothing was written).
	Changed bool
	// SettingsChanged is true when settings.json was rewritten; the merged
	// value is in Settings so a running mgmt server's cache can be updated.
	SettingsChanged bool
	Settings        models.GlobalSettings
	// PolicyChanged is true when the default policy file was rewritten.
	PolicyChanged bool
}

// ApplyManagedConfig applies (or clears) the managed-configuration document
// against the runtime files rooted at settingsPath. An empty document (no
// keys) means the device is no longer managed: managed.json is removed and
// previously applied values stay as-is but become editable again.
//
// The apply is atomic with respect to validation: both the settings merge
// and the policy merge are computed and validated before either file is
// written, so a bad EMM push can never half-apply.
func ApplyManagedConfig(settingsPath string, doc []byte) (ApplyResult, error) {
	trimmed := strings.TrimSpace(string(doc))
	if trimmed == "" {
		trimmed = "{}"
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return ApplyResult{}, &ValidationError{Msg: "invalid managed config document: " + err.Error()}
	}

	prev, err := config.LoadManagedState(settingsPath)
	if err != nil {
		return ApplyResult{}, err
	}

	// Empty doc => un-enrolled. Clearing an already-clear state is a no-op.
	if len(raw) == 0 {
		if !prev.Managed {
			return ApplyResult{}, nil
		}
		if err := config.ClearManagedState(settingsPath); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{Changed: true}, nil
	}

	var parsed ManagedDoc
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return ApplyResult{}, &ValidationError{Msg: "invalid managed config document: " + err.Error()}
	}

	hash, err := canonicalHash(raw)
	if err != nil {
		return ApplyResult{}, err
	}
	// Identical doc already applied => nothing to do. This short-circuit is
	// load-bearing: a mgmt_password restriction would otherwise be re-hashed
	// with a fresh scrypt salt on every application (every app start),
	// rewriting settings.json and invalidating every session each boot.
	if prev.Managed && prev.RestrictionsHash == hash {
		return ApplyResult{}, nil
	}

	// Compute and validate everything before writing anything.
	res := ApplyResult{Changed: true}

	cur, err := config.LoadSettings(settingsPath)
	if err != nil {
		return ApplyResult{}, err
	}
	mergedSettings := cur
	if len(parsed.Settings) > 0 {
		mergedSettings, err = MergeSettings(cur, parsed.Settings)
		if err != nil {
			return ApplyResult{}, err
		}
		res.SettingsChanged = true
	}
	res.Settings = mergedSettings

	store := config.NewPolicyStore(mergedSettings.PoliciesDir)
	var mergedPolicy models.Policy
	switch {
	case parsed.PolicyJSON != "":
		p := models.NewPolicy()
		if err := json.Unmarshal([]byte(parsed.PolicyJSON), &p); err != nil {
			return ApplyResult{}, &ValidationError{Msg: "invalid policy_json: " + err.Error()}
		}
		p.Name = "default"
		mergedPolicy = p
		res.PolicyChanged = true
	case len(parsed.Policy) > 0:
		curPolicy, err := store.Get("default")
		if errors.Is(err, config.ErrNotFound) {
			curPolicy = models.NewPolicy()
			curPolicy.Name = "default"
		} else if err != nil {
			return ApplyResult{}, err
		}
		mergedPolicy, err = MergePolicyPatch(curPolicy, parsed.Policy)
		if err != nil {
			return ApplyResult{}, err
		}
		mergedPolicy.Name = "default"
		res.PolicyChanged = true
	}

	// All merges validated - now write.
	if res.SettingsChanged {
		if err := config.SaveSettings(settingsPath, mergedSettings); err != nil {
			return ApplyResult{}, err
		}
	}
	if res.PolicyChanged {
		if err := store.Update("default", mergedPolicy); err != nil {
			if errors.Is(err, config.ErrNotFound) {
				err = store.Create(mergedPolicy)
			}
			if err != nil {
				return ApplyResult{}, err
			}
		}
	}
	if err := config.SaveManagedState(settingsPath, config.ManagedState{
		Managed:          true,
		SettingsLocked:   parsed.SettingsLocked,
		RestrictionsHash: hash,
		AppliedAt:        time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return ApplyResult{}, err
	}
	return res, nil
}

// canonicalHash hashes the document independent of key order and
// insignificant whitespace: encoding/json marshals maps with sorted keys,
// recursively, so re-marshaling the decoded document is a canonical form.
func canonicalHash(raw map[string]json.RawMessage) (string, error) {
	var generic map[string]any
	data, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &generic); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
