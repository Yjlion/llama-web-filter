package categories

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// DefaultUpdateURL is the IPFire squidGuard blocklist tarball, the same
// source scripts/update_categories.sh downloads.
const DefaultUpdateURL = "https://dbl.ipfire.org/lists/squidguard.tar.gz"

// ExtractDomainLists reads a gzipped tar archive in the IPFire squidGuard
// layout (a single top-level directory - "blacklists/" upstream - containing
// one subdirectory per category, each with a "domains" file) and returns raw
// domains-file bytes keyed by category name.
//
// Rather than hardcoding the "blacklists/" directory name, this picks
// whichever top-level directory contains the most "<name>/domains" entries -
// a generalization of the shell script's "try blacklists/, else the first
// dir with */domains" fallback that doesn't depend on the archive's exact
// top-level name.
func ExtractDomainLists(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	type key struct{ top, name string }
	raw := make(map[key][]byte)
	topCounts := make(map[string]int)

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		parts := strings.Split(strings.Trim(hdr.Name, "/"), "/")
		if len(parts) != 3 || parts[2] != "domains" {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		raw[key{parts[0], parts[1]}] = data
		topCounts[parts[0]]++
	}

	bestTop, bestCount := "", 0
	for top, c := range topCounts {
		if c > bestCount {
			bestTop, bestCount = top, c
		}
	}
	if bestTop == "" {
		return nil, fmt.Errorf("no */domains entries found in archive")
	}

	out := make(map[string][]byte, bestCount)
	for k, data := range raw {
		if k.top == bestTop {
			out[k.name] = data
		}
	}
	return out, nil
}

// cleanDomainList strips comments/blank lines, lowercases, and de-duplicates
// a raw domains-file blob, returning sorted domain lines.
func cleanDomainList(data []byte) []string {
	seen := make(map[string]struct{})
	lines := make([]string, 0)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// validCategoryName reports whether name is safe to use as a single
// category directory name below the categories destination. Archive category
// names are intentionally limited to a conservative portable allowlist.
func validCategoryName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, filepath.Separator) {
		return false
	}
	for _, r := range name {
		if r == '_' || r == '-' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

// WriteCategories cleans each category's domain list and writes
// destDir/<name>/domains + destDir/index.json, matching the format
// Store.List/IndexMeta read. If keep is non-empty, only category names
// present in keep are written (mirrors update_categories.sh's --keep
// whitelist); existing categories not present in lists are left untouched
// either way - this only ever adds/replaces, never prunes.
//
// Each category's directory is staged fully before being swapped into place
// via os.Rename (same-volume, atomic), so a crash mid-run can't leave a
// half-written domains file for a running proxy to read.
func WriteCategories(destDir, sourceURL string, lists map[string][]byte, keep map[string]bool) ([]Meta, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create categories dir: %w", err)
	}
	stageDir, err := os.MkdirTemp(destDir, ".stage-*")
	if err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stageDir)

	updated := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	metas := make([]Meta, 0, len(lists))

	for name, data := range lists {
		if len(keep) > 0 && !keep[name] {
			continue
		}
		if !validCategoryName(name) {
			return nil, fmt.Errorf("invalid archive category name %q", name)
		}
		domainLines := cleanDomainList(data)
		catStageDir := filepath.Join(stageDir, name)
		if err := os.MkdirAll(catStageDir, 0o755); err != nil {
			return nil, fmt.Errorf("stage category %s: %w", name, err)
		}
		content := strings.Join(domainLines, "\n")
		if len(domainLines) > 0 {
			content += "\n"
		}
		if err := os.WriteFile(filepath.Join(catStageDir, "domains"), []byte(content), 0o644); err != nil {
			return nil, fmt.Errorf("write %s/domains: %w", name, err)
		}
		metas = append(metas, Meta{Name: name, Count: len(domainLines), Updated: updated})
	}
	if len(metas) == 0 {
		return nil, fmt.Errorf("nothing to write: 0 categories matched (check --keep filter)")
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].Name < metas[j].Name })

	indexPayload := struct {
		Source     string `json:"source"`
		Updated    string `json:"updated"`
		Categories []Meta `json:"categories"`
	}{Source: sourceURL, Updated: updated, Categories: metas}
	indexData, err := json.MarshalIndent(indexPayload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal index.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "index.json"), indexData, 0o644); err != nil {
		return nil, fmt.Errorf("write staged index.json: %w", err)
	}

	for _, m := range metas {
		destCat := filepath.Join(destDir, m.Name)
		if err := os.RemoveAll(destCat); err != nil {
			return nil, fmt.Errorf("remove old %s: %w", m.Name, err)
		}
		if err := os.Rename(filepath.Join(stageDir, m.Name), destCat); err != nil {
			return nil, fmt.Errorf("swap in %s: %w", m.Name, err)
		}
	}
	if err := os.Rename(filepath.Join(stageDir, "index.json"), filepath.Join(destDir, "index.json")); err != nil {
		return nil, fmt.Errorf("swap in index.json: %w", err)
	}
	return metas, nil
}
