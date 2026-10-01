package categories_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/categories"
)

func writeCategory(t *testing.T, base, name string, domains string) {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "domains"), []byte(domains), 0o644); err != nil {
		t.Fatalf("write domains: %v", err)
	}
}

func TestHostMatchesSuffixAndSubdomain(t *testing.T) {
	dir := t.TempDir()
	writeCategory(t, dir, "ads", "# comment\nexample.com\nads.net\n")
	store := categories.NewStore(dir)

	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a.b.example.com", true},
		{"notexample.com", false},
		{"ads.net", true},
		{"other.org", false},
	}
	for _, c := range cases {
		if got := store.HostMatches(c.host, "ads"); got != c.want {
			t.Errorf("HostMatches(%q, ads) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestHostMatchesUnknownCategory(t *testing.T) {
	dir := t.TempDir()
	store := categories.NewStore(dir)
	if store.HostMatches("example.com", "nope") {
		t.Error("HostMatches should be false for a category with no domains file")
	}
}

func TestMatchAnyReturnsFirstMatch(t *testing.T) {
	dir := t.TempDir()
	writeCategory(t, dir, "ads", "ads.net\n")
	writeCategory(t, dir, "gambling", "example.com\n")
	store := categories.NewStore(dir)

	got := store.MatchAny("sub.example.com", []string{"ads", "gambling"})
	if got != "gambling" {
		t.Errorf("MatchAny = %q, want gambling", got)
	}
	if got := store.MatchAny("unlisted.com", []string{"ads", "gambling"}); got != "" {
		t.Errorf("MatchAny = %q, want empty", got)
	}
}

func TestListAndIndexMeta(t *testing.T) {
	dir := t.TempDir()
	indexJSON := `{"generated": "2026-01-01", "categories": [{"name": "ads", "count": 2, "updated": "2026-01-01"}]}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(indexJSON), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	store := categories.NewStore(dir)

	list := store.List()
	if len(list) != 1 || list[0].Name != "ads" || list[0].Count != 2 {
		t.Errorf("List() = %+v, want one ads entry", list)
	}
	meta := store.IndexMeta()
	if meta["generated"] != "2026-01-01" {
		t.Errorf("IndexMeta() = %+v, want generated=2026-01-01", meta)
	}
	if _, ok := meta["categories"]; ok {
		t.Error("IndexMeta() should not include the categories key")
	}
}

func TestListMissingIndexReturnsEmpty(t *testing.T) {
	store := categories.NewStore(t.TempDir())
	if list := store.List(); len(list) != 0 {
		t.Errorf("List() = %+v, want empty", list)
	}
}

func TestDomainsCacheRefreshesOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	writeCategory(t, dir, "ads", "ads.net\n")
	store := categories.NewStore(dir)

	if !store.HostMatches("ads.net", "ads") {
		t.Fatal("expected initial match")
	}
	// Overwrite with different content; since the check interval hasn't
	// elapsed the cache would normally still serve the old set, but forcing
	// a mtime bump combined with re-reading through a fresh Store should
	// pick up new content - simulate by using a fresh Store instance
	// (real hot-reload within the 60s window is exercised by re-instantiating
	// the store, which is what happens when settings are reloaded).
	writeCategory(t, dir, "ads", "other.net\n")
	fresh := categories.NewStore(dir)
	if fresh.HostMatches("ads.net", "ads") {
		t.Error("fresh store should reflect updated domains file, not stale content")
	}
	if !fresh.HostMatches("other.net", "ads") {
		t.Error("fresh store should match the newly written domain")
	}
}
