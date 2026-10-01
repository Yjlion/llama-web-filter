package adblock

import (
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Source is one downloadable filter list.
type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// DefaultSources are the lists fetched by `webfilter adblock update`.
// EasyList is the ad list, EasyPrivacy the tracker list; both are
// maintained at github.com/easylist/easylist and published at easylist.to.
var DefaultSources = []Source{
	{Name: "easylist", URL: "https://easylist.to/easylist/easylist.txt"},
	{Name: "easyprivacy", URL: "https://easylist.to/easylist/easyprivacy.txt"},
}

//go:embed snapshot/*.txt.gz
var snapshotFS embed.FS

// SnapshotDate records when the embedded lists were taken.
const SnapshotDate = "2026-10-01"

// LoadSnapshot parses the lists embedded in the binary, so ad blocking
// works offline and before the first update.
func LoadSnapshot() ([]Parsed, error) {
	entries, err := snapshotFS.ReadDir("snapshot")
	if err != nil {
		return nil, err
	}
	var out []Parsed
	for _, e := range entries {
		data, err := snapshotFS.ReadFile("snapshot/" + e.Name())
		if err != nil {
			return nil, err
		}
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, Parse(gz))
		gz.Close()
	}
	return out, nil
}

// State records what is on disk in a lists directory.
type State struct {
	Updated time.Time         `json:"updated"`
	Sources []Source          `json:"sources"`
	Sizes   map[string]int64  `json:"sizes"`
	Errors  map[string]string `json:"errors,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// LoadDir parses every *.txt in dir. ok=false when the directory holds no
// lists (the caller then uses the snapshot).
func LoadDir(dir string) ([]Parsed, State, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, State{}, false
	}
	var out []Parsed
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, Parse(f))
		f.Close()
	}
	var st State
	if data, err := os.ReadFile(statePath(dir)); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return out, st, len(out) > 0
}

// Update downloads sources into dir (atomically per file) and records
// the state. A source that fails leaves its previous file in place.
func Update(ctx context.Context, dir string, sources []Source, client *http.Client) (State, error) {
	if len(sources) == 0 {
		sources = DefaultSources
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return State{}, err
	}
	st := State{Updated: time.Now().UTC(), Sources: sources, Sizes: map[string]int64{}, Errors: map[string]string{}}
	var okCount int
	for _, s := range sources {
		name := safeName(s.Name)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
		if err != nil {
			st.Errors[name] = err.Error()
			continue
		}
		req.Header.Set("User-Agent", "llama-web-filter")
		resp, err := client.Do(req)
		if err != nil {
			st.Errors[name] = err.Error()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			st.Errors[name] = fmt.Sprintf("HTTP %d %v", resp.StatusCode, err)
			continue
		}
		if p := Parse(bytes.NewReader(data)); len(p.Network)+len(p.Cosmetic) < 10 {
			st.Errors[name] = "downloaded file does not look like a filter list"
			continue
		}
		dest := filepath.Join(dir, name+".txt")
		if err := os.WriteFile(dest+".tmp", data, 0o644); err != nil {
			st.Errors[name] = err.Error()
			continue
		}
		if err := os.Rename(dest+".tmp", dest); err != nil {
			st.Errors[name] = err.Error()
			continue
		}
		st.Sizes[name] = int64(len(data))
		okCount++
	}
	if len(st.Errors) == 0 {
		st.Errors = nil
	}
	data, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(statePath(dir), data, 0o644)
	if okCount == 0 {
		names := make([]string, 0, len(st.Errors))
		for n := range st.Errors {
			names = append(names, n+": "+st.Errors[n])
		}
		sort.Strings(names)
		return st, fmt.Errorf("no list could be downloaded: %s", strings.Join(names, "; "))
	}
	return st, nil
}

func safeName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	var b strings.Builder
	for _, r := range n {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "list"
	}
	return b.String()
}
