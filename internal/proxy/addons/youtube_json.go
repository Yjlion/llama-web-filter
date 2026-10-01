package addons

// Small helpers for navigating YouTube's undocumented, deeply-nested
// InnerTube JSON payloads as generic map[string]any/[]any trees - mirrors
// how youtube_filter.py works directly with Python dicts rather than
// typed structs (these payloads are large, semi-arbitrary, and only a
// handful of fields are ever read/mutated).

func getMap(parent map[string]any, key string) (map[string]any, bool) {
	if parent == nil {
		return nil, false
	}
	v, ok := parent[key]
	if !ok {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

func getSlice(parent map[string]any, key string) ([]any, bool) {
	if parent == nil {
		return nil, false
	}
	v, ok := parent[key]
	if !ok {
		return nil, false
	}
	s, ok := v.([]any)
	return s, ok
}

func getString(parent map[string]any, key string) string {
	if parent == nil {
		return ""
	}
	s, _ := parent[key].(string)
	return s
}
