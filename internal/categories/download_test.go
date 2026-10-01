package categories

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func listServer(t *testing.T, lists map[string]string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 || parts[1] != "domains.txt" {
			http.NotFound(w, r)
			return
		}
		body, ok := lists[parts[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestDownloadCategoryWritesGzAndIndex(t *testing.T) {
	ts := listServer(t, map[string]string{
		"gambling": "# header comment\nbet.example\nBET.example\ncasino.example\n\n",
	})
	dest := t.TempDir()

	// Pre-seed an index entry from "the tarball path"; it must survive.
	if err := upsertIndexEntry(dest, Meta{Name: "adult", Count: 3, Updated: "2026-01-01T00:00:00Z"}, "tarball"); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	meta, err := DownloadCategory(context.Background(), dest, ts.URL+"/", "gambling")
	if err != nil {
		t.Fatalf("DownloadCategory() error = %v", err)
	}
	if meta.Count != 2 {
		t.Errorf("Count = %d, want 2 (deduped, comments stripped)", meta.Count)
	}
	if _, err := os.Stat(filepath.Join(dest, "gambling", "domains.gz")); err != nil {
		t.Fatalf("domains.gz not written: %v", err)
	}

	s := NewStore(dest)
	if !s.HostMatches("casino.example", "gambling") || !s.HostMatches("m.bet.example", "gambling") {
		t.Error("downloaded list not matchable through the store")
	}

	metas := s.List()
	names := map[string]int{}
	for _, m := range metas {
		names[m.Name] = m.Count
	}
	if names["adult"] != 3 {
		t.Errorf("pre-existing index entry lost: %v", metas)
	}
	if names["gambling"] != 2 {
		t.Errorf("downloaded entry missing from index: %v", metas)
	}
}

func TestDownloadCategoryReplacesPlainFile(t *testing.T) {
	ts := listServer(t, map[string]string{"ads": "tracker.example\n"})
	dest := t.TempDir()
	dir := filepath.Join(dest, "ads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "domains"), []byte("old.example\n"), 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	if _, err := DownloadCategory(context.Background(), dest, ts.URL+"/", "ads"); err != nil {
		t.Fatalf("DownloadCategory() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "domains")); !os.IsNotExist(err) {
		t.Error("stale plain domains file survived the download swap")
	}
	if !NewStore(dest).HostMatches("tracker.example", "ads") {
		t.Error("fresh list not served after replacing a plain file")
	}
}

func TestDownloadCategoryErrors(t *testing.T) {
	ts := listServer(t, map[string]string{"ads": "x.example\n", "empty": "# nothing\n"})
	dest := t.TempDir()

	if _, err := DownloadCategory(context.Background(), dest, ts.URL+"/", "../evil"); err == nil {
		t.Error("path-traversal category name accepted")
	}
	if _, err := DownloadCategory(context.Background(), dest, ts.URL+"/", "missing"); err == nil {
		t.Error("HTTP 404 must be an error")
	}
	if _, err := DownloadCategory(context.Background(), dest, ts.URL+"/", "empty"); err == nil {
		t.Error("empty list must be an error")
	}
	if entries, err := os.ReadDir(dest); err == nil {
		for _, e := range entries {
			if e.Name() != "index.json" && !strings.HasPrefix(e.Name(), ".") {
				t.Errorf("failed downloads left %q behind", e.Name())
			}
		}
	}
}

func TestWriteCleanedGzEnforcesSizeCap(t *testing.T) {
	// An endless stream of unique lines must hit the byte cap, not OOM.
	r := &endlessLines{}
	if _, err := writeCleanedGz(filepath.Join(t.TempDir(), "domains.gz"), r); err == nil {
		t.Fatal("writeCleanedGz accepted an over-cap stream")
	} else if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// endlessLines yields distinct ~40-byte lines forever.
type endlessLines struct{ n int }

func (e *endlessLines) Read(p []byte) (int, error) {
	line := ""
	for len(line)+48 < len(p) {
		e.n++
		line += strings.Repeat("a", 32) + "-" + strconv.Itoa(e.n) + ".x\n"
	}
	if line == "" {
		e.n++
		line = strconv.Itoa(e.n) + ".x\n"
	}
	return copy(p, line), nil
}

func TestDeleteCategoryRemovesDirAndIndexEntry(t *testing.T) {
	ts := listServer(t, map[string]string{"ads": "x.example\n"})
	dest := t.TempDir()
	if _, err := DownloadCategory(context.Background(), dest, ts.URL+"/", "ads"); err != nil {
		t.Fatalf("DownloadCategory() error = %v", err)
	}

	if err := DeleteCategory(dest, "ads"); err != nil {
		t.Fatalf("DeleteCategory() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "ads")); !os.IsNotExist(err) {
		t.Error("category dir survived delete")
	}
	data, err := os.ReadFile(filepath.Join(dest, "index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var doc struct {
		Categories []Meta `json:"categories"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	for _, m := range doc.Categories {
		if m.Name == "ads" {
			t.Error("index entry survived delete")
		}
	}

	// Deleting something absent is a no-op, not an error.
	if err := DeleteCategory(dest, "never-there"); err != nil {
		t.Errorf("DeleteCategory(absent) error = %v", err)
	}
}
