package neighbors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseWiresharkManuf(t *testing.T) {
	data := "# Comment line\n" +
		"00:00:00\tXEROX\tXEROX CORPORATION\n" +
		"00:00:0C\tCisco\tCisco Systems, Inc\n" +
		"00:00:0C:00:00/28\tCiscoSub\tShould be skipped (MA-M)\n" +
		"AA:BB:CC\t\tOnly Long Name\n" +
		"ZZ:ZZ:ZZ\tBogus\tNot valid hex\n"

	table := ParseWiresharkManuf(strings.NewReader(data))

	if len(table) != 3 {
		t.Fatalf("len(table) = %d, want 3; table=%+v", len(table), table)
	}
	if table["000000"] != "XEROX" {
		t.Errorf(`table["000000"] = %q, want "XEROX"`, table["000000"])
	}
	if table["00000c"] != "Cisco" {
		t.Errorf(`table["00000c"] = %q, want "Cisco"`, table["00000c"])
	}
	if table["aabbcc"] != "Only Long Name" {
		t.Errorf(`table["aabbcc"] = %q, want fallback to long name`, table["aabbcc"])
	}
	if _, ok := table["00000c00"]; ok {
		t.Errorf("MA-M entry with /28 suffix should have been skipped")
	}
	if _, ok := table["zzzzzz"]; ok {
		t.Errorf("non-hex prefix should have been skipped")
	}
}

func TestWriteOuiFileAndVendorForRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oui.txt")

	table := map[string]string{
		"aabbcc": "Acme Corp",
		"001122": "Widget Inc",
	}
	if err := WriteOuiFile(path, "https://example.test/manuf", table); err != nil {
		t.Fatalf("WriteOuiFile: %v", err)
	}

	ConfigureOUI(path)
	t.Cleanup(func() { ConfigureOUI("") })
	// Force an immediate reload regardless of the mtime-check TTL.
	ouiMu.Lock()
	ouiLastCheck = ouiLastCheck.Add(-2 * ouiMtimeTTL)
	ouiMu.Unlock()

	if v := VendorFor("aa:bb:cc:11:22:33"); v != "Acme Corp" {
		t.Errorf("VendorFor(aa:bb:cc:...) = %q, want Acme Corp", v)
	}
	if v := VendorFor("00-11-22-33-44-55"); v != "Widget Inc" {
		t.Errorf("VendorFor(00-11-22-...) = %q, want Widget Inc", v)
	}
	if v := VendorFor("ff:ff:ff:ff:ff:ff"); v != "" {
		t.Errorf("VendorFor(unknown prefix) = %q, want empty", v)
	}
	if v := VendorFor(""); v != "" {
		t.Errorf("VendorFor(empty) = %q, want empty", v)
	}
}

func TestBuiltinOuiTableIsParseable(t *testing.T) {
	table := builtinOuiTable()
	if len(table) == 0 {
		t.Fatalf("embedded OUI table parsed 0 entries")
	}
	if table["000000"] == "" {
		t.Fatalf("embedded OUI table missing 00:00:00 test prefix")
	}
}

func TestVendorForUsesEmbeddedDefaultWhenFileMissing(t *testing.T) {
	t.Chdir(t.TempDir())
	ConfigureOUI("")
	t.Cleanup(func() { ConfigureOUI("") })
	// Force an immediate reload regardless of the mtime-check TTL.
	ouiMu.Lock()
	ouiLastCheck = ouiLastCheck.Add(-2 * ouiMtimeTTL)
	ouiMu.Unlock()

	if v := VendorFor("00:00:00:11:22:33"); v == "" {
		t.Errorf("VendorFor with missing default OUI file = empty, want embedded vendor")
	}
}

func TestVendorForFailsOpenWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	ConfigureOUI(filepath.Join(dir, "does-not-exist.txt"))
	t.Cleanup(func() { ConfigureOUI("") })

	if v := VendorFor("aa:bb:cc:11:22:33"); v != "" {
		t.Errorf("VendorFor with missing file = %q, want empty (fail open)", v)
	}
}

func TestConfigureOUIResetsToDefaultOnEmptyPath(t *testing.T) {
	ConfigureOUI("/some/custom/path.txt")
	ConfigureOUI("")
	ouiMu.Lock()
	got := ouiPath
	ouiMu.Unlock()
	if got != DefaultOuiPath {
		t.Errorf("ouiPath after ConfigureOUI(\"\") = %q, want %q", got, DefaultOuiPath)
	}
}

// Sanity check that WriteOuiFile's output is exactly what parseOuiFile (the
// runtime reader) expects - i.e. the two halves of the round trip actually
// agree on format, not just on behavior via the package's own VendorFor.
func TestWriteOuiFileFormatIsParseable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oui.txt")
	if err := WriteOuiFile(path, "src", map[string]string{"aabbcc": "Acme"}); err != nil {
		t.Fatalf("WriteOuiFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	table := parseOuiFile(f)
	if table["aabbcc"] != "Acme" {
		t.Errorf("round-tripped table = %+v, want aabbcc -> Acme", table)
	}
}
