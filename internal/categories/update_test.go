package categories

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestTarGz mimics the IPFire squidGuard archive layout: one top-level
// dir ("blacklists"), one subdir per category, each with a domains file
// (plus noise files/dirs that should be ignored).
func buildTestTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	files := map[string]string{
		"blacklists/gambling/domains":     "# comment\nBet365.com\ngambling-site.net\nbet365.com\n\n",
		"blacklists/gambling/urls":        "should-be-ignored.com/path\n",
		"blacklists/gambling/expressions": "ignored-too\n",
		"blacklists/porn/domains":         "adult-site.com\nANOTHER.example\n",
		// A decoy top-level dir with fewer entries - should lose to "blacklists".
		"decoy/onlyone/domains": "decoy.example\n",
	}
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write content %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func TestExtractDomainListsPicksDenserTopDir(t *testing.T) {
	data := buildTestTarGz(t)
	lists, err := ExtractDomainLists(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ExtractDomainLists: %v", err)
	}
	if len(lists) != 2 {
		t.Fatalf("len(lists) = %d, want 2 (gambling, porn); got %v", len(lists), keysOf(lists))
	}
	if _, ok := lists["gambling"]; !ok {
		t.Errorf("missing gambling category")
	}
	if _, ok := lists["porn"]; !ok {
		t.Errorf("missing porn category")
	}
	if _, ok := lists["onlyone"]; ok {
		t.Errorf("decoy top-level dir's category should have been excluded")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCleanDomainListDedupesAndLowercases(t *testing.T) {
	got := cleanDomainList([]byte("# comment\nBet365.com\ngambling-site.net\nbet365.com\n\n"))
	want := []string{"bet365.com", "gambling-site.net"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestWriteCategoriesAndStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	lists := map[string][]byte{
		"gambling": []byte("Bet365.com\ngambling-site.net\nbet365.com\n"),
		"porn":     []byte("adult-site.com\n"),
	}

	metas, err := WriteCategories(dir, "https://example.test/list.tar.gz", lists, nil)
	if err != nil {
		t.Fatalf("WriteCategories: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("len(metas) = %d, want 2", len(metas))
	}

	// gambling should have been deduped to 2 domains.
	var gambling Meta
	for _, m := range metas {
		if m.Name == "gambling" {
			gambling = m
		}
	}
	if gambling.Count != 2 {
		t.Errorf("gambling.Count = %d, want 2 (deduped)", gambling.Count)
	}

	domainsBytes, err := os.ReadFile(filepath.Join(dir, "gambling", "domains"))
	if err != nil {
		t.Fatalf("read domains file: %v", err)
	}
	if string(domainsBytes) != "bet365.com\ngambling-site.net\n" {
		t.Errorf("domains file content = %q", string(domainsBytes))
	}

	// The store built on top of this package should now see the same data.
	store := NewStore(dir)
	storeMetas := store.List()
	if len(storeMetas) != 2 {
		t.Fatalf("store.List() len = %d, want 2", len(storeMetas))
	}
	if !store.HostMatches("bet365.com", "gambling") {
		t.Errorf("store.HostMatches(bet365.com, gambling) = false, want true")
	}
	if store.HostMatches("bet365.com", "porn") {
		t.Errorf("store.HostMatches(bet365.com, porn) = true, want false")
	}

	// No staging directory should be left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "gambling" || e.Name() == "porn" || e.Name() == "index.json" {
			continue
		}
		t.Errorf("unexpected leftover entry in categories dir: %s", e.Name())
	}
}

func TestWriteCategoriesKeepFilter(t *testing.T) {
	dir := t.TempDir()
	lists := map[string][]byte{
		"gambling": []byte("bet365.com\n"),
		"porn":     []byte("adult-site.com\n"),
	}
	metas, err := WriteCategories(dir, "src", lists, map[string]bool{"gambling": true})
	if err != nil {
		t.Fatalf("WriteCategories: %v", err)
	}
	if len(metas) != 1 || metas[0].Name != "gambling" {
		t.Fatalf("metas = %+v, want only gambling", metas)
	}
	if _, err := os.Stat(filepath.Join(dir, "porn")); !os.IsNotExist(err) {
		t.Errorf("porn dir should not have been written when keep filter excludes it")
	}
}

func TestWriteCategoriesReplacesExistingCategory(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteCategories(dir, "src", map[string][]byte{"gambling": []byte("old-site.com\n")}, nil); err != nil {
		t.Fatalf("first WriteCategories: %v", err)
	}
	if _, err := WriteCategories(dir, "src", map[string][]byte{"gambling": []byte("new-site.com\n")}, nil); err != nil {
		t.Fatalf("second WriteCategories: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "gambling", "domains"))
	if err != nil {
		t.Fatalf("read domains: %v", err)
	}
	if string(data) != "new-site.com\n" {
		t.Errorf("domains after replace = %q, want only new-site.com (old file entry gone)", string(data))
	}
}

func TestIndexJSONIsValidAfterUpdate(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteCategories(dir, "https://src.example/list.tar.gz", map[string][]byte{"gambling": []byte("a.com\n")}, nil); err != nil {
		t.Fatalf("WriteCategories: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var parsed struct {
		Source     string `json:"source"`
		Updated    string `json:"updated"`
		Categories []Meta `json:"categories"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("index.json is not valid JSON: %v", err)
	}
	if parsed.Source != "https://src.example/list.tar.gz" {
		t.Errorf("source = %q", parsed.Source)
	}
	if len(parsed.Categories) != 1 || parsed.Categories[0].Name != "gambling" {
		t.Errorf("categories = %+v", parsed.Categories)
	}
}

func TestWriteCategoriesRejectsInvalidArchiveCategoryNames(t *testing.T) {
	for _, tc := range []struct {
		name string
	}{
		{name: ".."},
		{name: "nested/evil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "categories")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir categories: %v", err)
			}

			outsideFile := filepath.Join(parent, "outside.txt")
			if err := os.WriteFile(outsideFile, []byte("keep me"), 0o644); err != nil {
				t.Fatalf("write outside sentinel: %v", err)
			}
			insideFile := filepath.Join(dir, "existing.txt")
			if err := os.WriteFile(insideFile, []byte("existing"), 0o644); err != nil {
				t.Fatalf("write inside sentinel: %v", err)
			}

			_, err := WriteCategories(dir, "src", map[string][]byte{tc.name: []byte("evil.example\n")}, nil)
			if err == nil {
				t.Fatalf("WriteCategories with category name %q succeeded, want error", tc.name)
			}
			if !strings.Contains(err.Error(), "invalid archive category name") {
				t.Fatalf("WriteCategories error = %q, want invalid archive category name", err)
			}

			outsideData, err := os.ReadFile(outsideFile)
			if err != nil {
				t.Fatalf("outside sentinel should still exist: %v", err)
			}
			if string(outsideData) != "keep me" {
				t.Fatalf("outside sentinel = %q, want unchanged", outsideData)
			}
			insideData, err := os.ReadFile(insideFile)
			if err != nil {
				t.Fatalf("inside sentinel should still exist: %v", err)
			}
			if string(insideData) != "existing" {
				t.Fatalf("inside sentinel = %q, want unchanged", insideData)
			}
			if _, err := os.Stat(filepath.Join(parent, "evil")); !os.IsNotExist(err) {
				t.Fatalf("unexpected path outside destination was created; stat err = %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "nested")); !os.IsNotExist(err) {
				t.Fatalf("unexpected nested category path was created; stat err = %v", err)
			}
		})
	}
}
