package categories

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultListBaseURL is the IPFire per-category list root: each category
// lives at <base><name>/domains.txt as a plain one-domain-per-line file
// (the same data the squidguard tarball bundles).
const DefaultListBaseURL = "https://dbl.ipfire.org/lists/"

// KnownRemoteCategories are the per-category lists published under
// DefaultListBaseURL (verified 2026-07). The Android UI offers exactly
// these for download; the server does not expose a machine-readable index.
var KnownRemoteCategories = []string{
	"ads", "dating", "doh", "gambling", "games", "malware", "phishing",
	"piracy", "porn", "shopping", "smart-tv", "social", "streaming",
	"violence",
}

// maxCategoryDownloadBytes caps a single list download (the largest list,
// porn, is ~15 MB today; 64 MB leaves generous headroom while still
// bounding a misbehaving server).
const maxCategoryDownloadBytes = 64 << 20

// indexMu serializes index.json read-modify-write cycles across concurrent
// per-category downloads/deletes in this process.
var indexMu sync.Mutex

// DownloadCategory fetches one category list from <baseURL><name>/domains.txt,
// cleans it (lowercase, comments/blanks stripped, deduped), and installs it
// as destDir/<name>/domains.gz plus an index.json upsert. The cleaning is
// streamed straight into the gzip writer with a hash-based dedupe set, so
// even the million-line lists never materialize in memory. The category
// directory is staged and swapped in atomically; a crash mid-download can't
// leave a half-written list for a running proxy.
func DownloadCategory(ctx context.Context, destDir, baseURL, name string) (Meta, error) {
	if !validCategoryName(name) {
		return Meta{}, fmt.Errorf("invalid category name %q", name)
	}
	if baseURL == "" {
		baseURL = DefaultListBaseURL
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	url := baseURL + name + "/domains.txt"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Meta{}, fmt.Errorf("build request: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return Meta{}, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Meta{}, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return Meta{}, fmt.Errorf("create categories dir: %w", err)
	}
	stageDir, err := os.MkdirTemp(destDir, ".dl-*")
	if err != nil {
		return Meta{}, fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stageDir)
	catStageDir := filepath.Join(stageDir, name)
	if err := os.MkdirAll(catStageDir, 0o755); err != nil {
		return Meta{}, fmt.Errorf("stage category: %w", err)
	}

	count, err := writeCleanedGz(filepath.Join(catStageDir, "domains.gz"), resp.Body)
	if err != nil {
		return Meta{}, fmt.Errorf("write %s: %w", name, err)
	}
	if count == 0 {
		return Meta{}, fmt.Errorf("download %s: list is empty", url)
	}

	destCat := filepath.Join(destDir, name)
	if err := os.RemoveAll(destCat); err != nil {
		return Meta{}, fmt.Errorf("remove old %s: %w", name, err)
	}
	if err := os.Rename(catStageDir, destCat); err != nil {
		return Meta{}, fmt.Errorf("swap in %s: %w", name, err)
	}

	meta := Meta{
		Name:    name,
		Count:   count,
		Updated: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if err := upsertIndexEntry(destDir, meta, baseURL); err != nil {
		return Meta{}, err
	}
	return meta, nil
}

// DeleteCategory removes a downloaded category's directory and its
// index.json entry. Deleting a category that does not exist is a no-op.
func DeleteCategory(destDir, name string) error {
	if !validCategoryName(name) {
		return fmt.Errorf("invalid category name %q", name)
	}
	if err := os.RemoveAll(filepath.Join(destDir, name)); err != nil {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return removeIndexEntry(destDir, name)
}

// writeCleanedGz streams raw list lines into a gzipped, cleaned domains
// file and returns the number of unique domains written. Deduping uses a
// set of 64-bit line hashes (~8 MB per million lines) instead of the
// strings themselves.
func writeCleanedGz(path string, r io.Reader) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	w := bufio.NewWriter(gz)

	seen := make(map[uint64]struct{})
	count := 0
	var total int64
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		total += int64(len(scanner.Bytes())) + 1
		if total > maxCategoryDownloadBytes {
			return 0, fmt.Errorf("list exceeds %d MB cap", maxCategoryDownloadBytes>>20)
		}
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h := fnv1aHash(line)
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		if _, err := w.WriteString(line); err != nil {
			return 0, err
		}
		if err := w.WriteByte('\n'); err != nil {
			return 0, err
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	return count, f.Close()
}

// indexDoc mirrors the index.json layout WriteCategories produces; this
// package is the only writer of the file.
type indexDoc struct {
	Source     string `json:"source"`
	Updated    string `json:"updated"`
	Categories []Meta `json:"categories"`
}

func readIndex(destDir string) indexDoc {
	var doc indexDoc
	data, err := os.ReadFile(filepath.Join(destDir, "index.json"))
	if err == nil {
		_ = json.Unmarshal(data, &doc)
	}
	return doc
}

func writeIndex(destDir string, doc indexDoc) error {
	sort.Slice(doc.Categories, func(i, j int) bool { return doc.Categories[i].Name < doc.Categories[j].Name })
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal index.json: %w", err)
	}
	tmp := filepath.Join(destDir, ".index.json.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write index.json: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(destDir, "index.json")); err != nil {
		return fmt.Errorf("swap in index.json: %w", err)
	}
	return nil
}

// upsertIndexEntry replaces or appends one category's metadata, preserving
// entries written by the tarball update path.
func upsertIndexEntry(destDir string, m Meta, source string) error {
	indexMu.Lock()
	defer indexMu.Unlock()
	doc := readIndex(destDir)
	if doc.Source == "" {
		doc.Source = source
	}
	doc.Updated = m.Updated
	replaced := false
	for i := range doc.Categories {
		if doc.Categories[i].Name == m.Name {
			doc.Categories[i] = m
			replaced = true
			break
		}
	}
	if !replaced {
		doc.Categories = append(doc.Categories, m)
	}
	return writeIndex(destDir, doc)
}

func removeIndexEntry(destDir, name string) error {
	indexMu.Lock()
	defer indexMu.Unlock()
	doc := readIndex(destDir)
	kept := doc.Categories[:0]
	for _, m := range doc.Categories {
		if m.Name != name {
			kept = append(kept, m)
		}
	}
	if len(kept) == len(doc.Categories) {
		return nil // nothing to do; don't touch the file
	}
	doc.Categories = kept
	return writeIndex(destDir, doc)
}
