// Package categories implements shared site-category domain blocklists,
// mirroring shared/categories.py. Categories are domain lists shared
// across all policies, populated on disk by `webfilter categories update`
// (the IPFire squidGuard tarball) or per-category downloads
// (DownloadCategory, used by the Android native UI) under:
//
//	categories/index.json        [{name, count, updated}, ...] + metadata
//	categories/<name>/domains    one domain per line ('#' comments allowed)
//	categories/<name>/domains.gz gzip of the same format (preferred when
//	                             both exist; the per-category downloader
//	                             writes this to keep large lists small)
//
// A policy references categories by name via url_filter.categories. Domain
// sets are loaded lazily and cached, with the file mtime re-checked at most
// once per checkInterval so an update via the script is picked up without a
// restart but without a stat() on every request. Large sets are held as
// sorted 64-bit hashes rather than a string map (see domainSet) so a
// million-domain list costs ~8 MB instead of ~100 MB — important on
// Android.
package categories

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const checkInterval = 60 * time.Second

// hashSetThreshold is the domain count above which a set is stored as
// sorted hashes instead of an exact string map. 64-bit FNV-1a collisions at
// this scale are ~n/2^64 per lookup, and the failure mode is an over-block
// of one unlucky domain, not a filtering bypass.
const hashSetThreshold = 100_000

// domainSet is the read interface both representations satisfy.
type domainSet interface {
	contains(domain string) bool
	size() int
}

// mapSet is the exact representation for small sets.
type mapSet map[string]struct{}

func (m mapSet) contains(domain string) bool { _, ok := m[domain]; return ok }
func (m mapSet) size() int                   { return len(m) }

// hashSet is the compact representation for large sets: sorted FNV-1a 64
// hashes probed by binary search.
type hashSet []uint64

func (h hashSet) contains(domain string) bool {
	v := fnv1aHash(domain)
	i := sort.Search(len(h), func(i int) bool { return h[i] >= v })
	return i < len(h) && h[i] == v
}

func (h hashSet) size() int { return len(h) }

func fnv1aHash(s string) uint64 {
	const offset, prime = uint64(14695981039346656037), uint64(1099511628211)
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

// Meta is one entry in index.json's "categories" array.
type Meta struct {
	Name    string `json:"name"`
	Count   int    `json:"count"`
	Updated string `json:"updated"`
}

type cacheEntry struct {
	mtime   time.Time
	domains domainSet
	checked time.Time
}

// Store is a lazily-loaded, mtime-cached reader over a categories
// directory. The zero value is not usable; construct with NewStore.
type Store struct {
	mu   sync.Mutex
	base string
	// cache is guarded by mu; entries persist across Configure/base changes
	// only implicitly (a base change simply means old cached names retain
	// stale data until re-requested, mirroring the Python singleton's own
	// behavior of never clearing _cache on configure()).
	cache map[string]*cacheEntry
}

// NewStore constructs a Store rooted at base (normally settings.CategoriesDir).
func NewStore(base string) *Store {
	return &Store{base: base, cache: make(map[string]*cacheEntry)}
}

// Configure repoints the store at a different categories directory -
// used when settings.json's categories_dir changes underneath a running
// process (mirrors categories.configure()).
func (s *Store) Configure(base string) {
	s.mu.Lock()
	s.base = base
	s.mu.Unlock()
}

func (s *Store) indexPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filepath.Join(s.base, "index.json")
}

// List returns category metadata from the on-disk index (empty if not
// populated yet).
func (s *Store) List() []Meta {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return []Meta{}
	}
	var parsed struct {
		Categories []Meta `json:"categories"`
	}
	if json.Unmarshal(data, &parsed) != nil {
		return []Meta{}
	}
	if parsed.Categories == nil {
		return []Meta{}
	}
	return parsed.Categories
}

// IndexMeta returns every top-level key of index.json except "categories"
// (e.g. a last-updated timestamp for the whole index).
func (s *Store) IndexMeta() map[string]any {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return map[string]any{}
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return map[string]any{}
	}
	delete(raw, "categories")
	return raw
}

// domainsFile resolves the on-disk file for a category, preferring the
// compressed form the per-category downloader writes.
func domainsFile(base, name string) (path string, gzipped bool, info os.FileInfo, err error) {
	path = filepath.Join(base, name, "domains.gz")
	if info, err = os.Stat(path); err == nil {
		return path, true, info, nil
	}
	path = filepath.Join(base, name, "domains")
	info, err = os.Stat(path)
	return path, false, info, err
}

// domains returns the cached (or freshly loaded) domain set for name.
func (s *Store) domains(name string) domainSet {
	s.mu.Lock()
	base := s.base
	entry := s.cache[name]
	now := time.Now()
	if entry != nil && now.Sub(entry.checked) < checkInterval {
		s.mu.Unlock()
		return entry.domains
	}
	s.mu.Unlock()

	path, gzipped, info, err := domainsFile(base, name)
	if err != nil {
		s.mu.Lock()
		s.cache[name] = &cacheEntry{domains: mapSet{}, checked: now}
		s.mu.Unlock()
		return mapSet{}
	}
	mtime := info.ModTime()

	s.mu.Lock()
	entry = s.cache[name]
	if entry != nil && entry.mtime.Equal(mtime) {
		entry.checked = now
		domains := entry.domains
		s.mu.Unlock()
		return domains
	}
	s.mu.Unlock()

	loaded := loadDomains(path, gzipped)
	s.mu.Lock()
	s.cache[name] = &cacheEntry{mtime: mtime, domains: loaded, checked: now}
	s.mu.Unlock()
	return loaded
}

func loadDomains(path string, gzipped bool) domainSet {
	f, err := os.Open(path)
	if err != nil {
		return mapSet{}
	}
	defer f.Close()

	var r io.Reader = f
	if gzipped {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return mapSet{}
		}
		defer gz.Close()
		r = gz
	}
	return buildDomainSet(r)
}

// buildDomainSet streams domain lines into the cheapest adequate
// representation: an exact string map up to hashSetThreshold entries, then
// it degrades to hashes only (dropping the map) so a million-domain list
// never materializes as Go strings.
func buildDomainSet(r io.Reader) domainSet {
	exact := make(mapSet)
	var hashes hashSet
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hashes = append(hashes, fnv1aHash(line))
		if exact != nil {
			exact[line] = struct{}{}
			if len(exact) > hashSetThreshold {
				exact = nil // too big for exact strings; hashes take over
			}
		}
	}
	if exact != nil {
		return exact
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })
	// Dedupe in place (the source lists usually are unique, but the
	// binary-search contract wants sorted-unique anyway).
	out := hashes[:0]
	var prev uint64
	for i, h := range hashes {
		if i > 0 && h == prev {
			continue
		}
		out = append(out, h)
		prev = h
	}
	return out
}

// hostInSet checks host and each of its parent domains (stopping before
// the bare TLD) against domains - a registrable-suffix match.
func hostInSet(host string, domains domainSet) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1; i++ {
		if domains.contains(strings.Join(labels[i:], ".")) {
			return true
		}
	}
	return false
}

// HostMatches reports whether host (or a parent domain) is listed under
// category name.
func (s *Store) HostMatches(host, name string) bool {
	return hostInSet(host, s.domains(name))
}

// MatchAny returns the first category in names whose set contains host (or
// a parent domain), or "" if none match.
func (s *Store) MatchAny(host string, names []string) string {
	for _, name := range names {
		if name == "" {
			continue
		}
		if s.HostMatches(host, name) {
			return name
		}
	}
	return ""
}
