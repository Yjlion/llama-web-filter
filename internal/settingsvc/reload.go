package settingsvc

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// hotFields are the settings.json fields that take effect without
// restarting, named by their JSON tag. Everything not listed here is treated
// as restart-required.
//
// Defaulting to restart-required is the point: an unrecognised field is
// either brand new or something nobody classified, and the safe answer for
// both is "tell the operator to restart" rather than "silently claim it
// applied". TestEverySettingsFieldIsClassified fails when a field is added
// without a decision being made about it.
//
// A field belongs here only when every consumer reads it per request. That
// was checked call site by call site:
//
//   - ui_language           internal/proxy/block.go (per block page)
//   - mgmt_hostname[_ip]    addons/management_access.go (per request)
//   - proxy_auth_*          addons/proxy_auth.go (per request/CONNECT/SOCKS5)
//   - icap.*                internal/proxy/icap.go (per ICAP transaction)
//   - categories_dir        re-pointed via categories.Store.Configure
//   - oui_path              neighbors.ConfigureOUI, already reconfigured live
//   - auth_enabled,         mgmtapi middleware/auth read these through
//     password_hash,        Server.Settings() on every request, so they are
//     secret_key            already hot today
//   - pac_*                 mgmtapi routes_pac.go (per request)
//   - metrics_enabled,      mgmtapi routes_ops.go / middleware.go, read
//     metrics_token         through Server.Settings() per scrape
//   - default_policy        no runtime consumer at all
//
// Nested objects are classified as a whole: "icap" covers every icap.*
// field, because all of them are read from the same per-transaction
// snapshot.
var hotFields = map[string]bool{
	"ui_language":              true,
	"mgmt_hostname":            true,
	"mgmt_hostname_ip":         true,
	"proxy_auth_enabled":       true,
	"proxy_auth_username":      true,
	"proxy_auth_password_hash": true,
	"icap":                     true,
	"categories_dir":           true,
	"oui_path":                 true,
	"auth_enabled":             true,
	"password_hash":            true,
	"secret_key":               true,
	"pac_proxy_host":           true,
	"pac_direct_hosts":         true,
	"pac_direct_ips":           true,
	"metrics_enabled":          true,
	"metrics_token":            true,
	"default_policy":           true,

	// Deprecated and ignored by every consumer; listed so changing it never
	// tells anyone to restart for nothing.
	"text_classifier_model_path": true,
}

// IsHotField reports whether a settings field (named by its JSON tag) takes
// effect without a restart.
func IsHotField(jsonName string) bool { return hotFields[jsonName] }

// Change is one settings field that differs between two snapshots, named by
// its JSON tag ("proxy_listen", "icap").
type Change struct {
	Field string
	Hot   bool
}

// DiffSettings reports every top-level field whose value differs between old
// and next, in JSON-tag name order.
//
// The comparison is done on the marshalled JSON rather than by walking the
// Go values, so slices, pointers (default_policy) and nested config structs
// all compare by value without a type switch per field, and the field names
// it reports are exactly the ones an operator sees in settings.json and the
// API.
func DiffSettings(old, next models.GlobalSettings) []Change {
	oldMap := toFieldMap(old)
	nextMap := toFieldMap(next)

	names := make(map[string]bool, len(oldMap)+len(nextMap))
	for k := range oldMap {
		names[k] = true
	}
	for k := range nextMap {
		names[k] = true
	}

	var changes []Change
	for name := range names {
		if string(oldMap[name]) == string(nextMap[name]) {
			continue
		}
		changes = append(changes, Change{Field: name, Hot: hotFields[name]})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Field < changes[j].Field })
	return changes
}

// RestartRequired returns the names of the changed fields that will not take
// effect until the process restarts. An empty result means the change
// applied in full.
func RestartRequired(old, next models.GlobalSettings) []string {
	out := []string{}
	for _, c := range DiffSettings(old, next) {
		if !c.Hot {
			out = append(out, c.Field)
		}
	}
	return out
}

// MergeHot returns live with only the hot fields taken from next, keeping
// every restart-required field at the value that is actually in effect.
//
// This is what makes a partial reload safe to expose. Swapping the whole
// snapshot instead would let a live reader see, say, a new mgmt_port the
// moment it was saved - and addons/management_access.go builds its redirect
// from exactly that value, so it would start sending clients to a port
// nothing is bound to. The live snapshot must never contradict what is
// actually running.
func MergeHot(live, next models.GlobalSettings) models.GlobalSettings {
	liveMap := toFieldMap(live)
	nextMap := toFieldMap(next)

	merged := make(map[string]json.RawMessage, len(liveMap))
	for name, raw := range liveMap {
		if hotFields[name] {
			if hot, ok := nextMap[name]; ok {
				merged[name] = hot
				continue
			}
		}
		merged[name] = raw
	}
	// A hot field present only in next (a field added to the struct since
	// live was marshalled cannot happen, but be explicit rather than lossy).
	for name, raw := range nextMap {
		if _, ok := merged[name]; !ok && hotFields[name] {
			merged[name] = raw
		}
	}

	data, err := json.Marshal(merged)
	if err != nil {
		return live
	}
	var out models.GlobalSettings
	if err := json.Unmarshal(data, &out); err != nil {
		return live
	}
	return out
}

// toFieldMap marshals s and returns its top-level fields as raw JSON, keyed
// by JSON tag.
func toFieldMap(s models.GlobalSettings) map[string]json.RawMessage {
	data, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// SettingsFieldNames lists every JSON field name GlobalSettings declares,
// including omitempty fields that a marshalled zero value would drop. Used
// by the test that enforces every field being classified.
func SettingsFieldNames() []string {
	var names []string
	t := reflect.TypeOf(models.GlobalSettings{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
