package settingsvc

import (
	"encoding/json"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// MergePolicyPatch deep-merges patch into cur using RFC 7386
// JSON-merge-patch semantics (objects recurse, scalars/arrays replace, null
// deletes) and round-trips the result through models.Policy so defaults,
// validation, and normalization (MAC canonicalization, schedule window
// normalization) all apply.
//
// This exists because every policy sub-config's UnmarshalJSON resets the
// whole sub-config to defaults before overlaying the input: unmarshaling a
// partial body like {"text_classifier":{"enabled":true}} directly over an
// existing policy would silently reset that sub-config's other fields (a
// custom threshold, exclude list, ...) back to their defaults. Merging at
// the raw-JSON level first means only the keys actually present in the
// patch change.
func MergePolicyPatch(cur models.Policy, patch []byte) (models.Policy, error) {
	curRaw, err := json.Marshal(cur)
	if err != nil {
		return models.Policy{}, err
	}
	var curMap map[string]any
	if err := json.Unmarshal(curRaw, &curMap); err != nil {
		return models.Policy{}, err
	}
	var patchMap map[string]any
	if err := json.Unmarshal(patch, &patchMap); err != nil {
		return models.Policy{}, &ValidationError{Msg: "invalid policy patch: " + err.Error()}
	}

	merged := mergeJSONObjects(curMap, patchMap)
	mergedRaw, err := json.Marshal(merged)
	if err != nil {
		return models.Policy{}, err
	}
	p := models.NewPolicy()
	if err := json.Unmarshal(mergedRaw, &p); err != nil {
		return models.Policy{}, &ValidationError{Msg: "invalid policy patch: " + err.Error()}
	}
	return p, nil
}

// mergeJSONObjects implements RFC 7386 over decoded JSON values: for each
// patch key, null deletes, nested objects recurse, everything else
// (scalars and arrays) replaces the target value.
func mergeJSONObjects(target, patch map[string]any) map[string]any {
	out := make(map[string]any, len(target)+len(patch))
	for k, v := range target {
		out[k] = v
	}
	for k, pv := range patch {
		if pv == nil {
			delete(out, k)
			continue
		}
		pObj, pIsObj := pv.(map[string]any)
		if !pIsObj {
			out[k] = pv
			continue
		}
		tObj, tIsObj := out[k].(map[string]any)
		if !tIsObj {
			tObj = map[string]any{}
		}
		out[k] = mergeJSONObjects(tObj, pObj)
	}
	return out
}
