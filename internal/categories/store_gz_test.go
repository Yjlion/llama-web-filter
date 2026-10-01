package categories

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGzDomains(t *testing.T, base, name, content string) {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Create(filepath.Join(dir, "domains.gz"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestStoreReadsGzippedDomains(t *testing.T) {
	base := t.TempDir()
	writeGzDomains(t, base, "adult", "# comment\nbad.example\nWORSE.example\n")

	s := NewStore(base)
	if !s.HostMatches("bad.example", "adult") {
		t.Error("HostMatches(bad.example) = false, want true from domains.gz")
	}
	if !s.HostMatches("cdn.worse.example", "adult") {
		t.Error("parent-suffix match through domains.gz failed")
	}
	if s.HostMatches("good.example", "adult") {
		t.Error("HostMatches(good.example) = true, want false")
	}
}

func TestStorePrefersGzOverPlain(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "adult")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Stale plain file lists a different domain than the fresh .gz.
	if err := os.WriteFile(filepath.Join(dir, "domains"), []byte("stale.example\n"), 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	writeGzDomains(t, base, "adult", "fresh.example\n")

	s := NewStore(base)
	if !s.HostMatches("fresh.example", "adult") {
		t.Error("gz content not used when both files exist")
	}
	if s.HostMatches("stale.example", "adult") {
		t.Error("stale plain file used despite a domains.gz being present")
	}
}

// TestLargeSetsDegradeToHashesWithSameAnswers pins both the representation
// switch above hashSetThreshold and lookup parity across the two forms.
func TestLargeSetsDegradeToHashesWithSameAnswers(t *testing.T) {
	var b strings.Builder
	n := hashSetThreshold + 5
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "site-%d.example\n", i)
	}
	big := buildDomainSet(strings.NewReader(b.String()))
	if _, ok := big.(hashSet); !ok {
		t.Fatalf("set of %d domains is %T, want hashSet", n, big)
	}
	if big.size() != n {
		t.Errorf("size() = %d, want %d", big.size(), n)
	}

	small := buildDomainSet(strings.NewReader("site-0.example\nsite-1.example\n"))
	if _, ok := small.(mapSet); !ok {
		t.Fatalf("small set is %T, want mapSet", small)
	}

	for _, host := range []string{"site-0.example", "site-1.example"} {
		for _, set := range []domainSet{big, small} {
			if !hostInSet(host, set) {
				t.Errorf("%T missing %s", set, host)
			}
			if !hostInSet("deep.sub."+host, set) {
				t.Errorf("%T parent-suffix match failed for %s", set, host)
			}
		}
	}
	for _, set := range []domainSet{big, small} {
		if hostInSet("absent.example", set) {
			t.Errorf("%T matched a domain that is not listed", set)
		}
	}
}
