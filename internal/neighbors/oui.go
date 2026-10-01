package neighbors

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultOuiPath is where the IEEE OUI vendor lookup table lives when
// GlobalSettings.OuiPath is unset, mirroring the Python original's
// hardcoded shared/data/oui.txt (this port makes the location configurable,
// but keeps the same file format so `webfilter oui update`'s output is a
// drop-in replacement).
//
// File format: one entry per line, "<6-hex-lowercase-prefix><TAB><Vendor
// Name>". Comment lines ('#') and blank lines are skipped.
const DefaultOuiPath = "./data/oui.txt"

const ouiMtimeTTL = 60 * time.Second

//go:embed oui.txt
var builtinOuiManuf string

var (
	ouiMu        sync.Mutex
	ouiPath      = DefaultOuiPath
	ouiTable     map[string]string
	ouiLoadedAt  time.Time // mtime of the currently-cached file
	ouiLastCheck time.Time
)

// ConfigureOUI repoints the vendor lookup at a different oui.txt path -
// mirrors categories.Store.Configure. An empty path resets to
// DefaultOuiPath. Does not itself trigger a reload; VendorFor reloads lazily
// on next use if the effective path or the file's mtime changed.
func ConfigureOUI(path string) {
	ouiMu.Lock()
	defer ouiMu.Unlock()
	if path == "" {
		path = DefaultOuiPath
	}
	if path != ouiPath {
		ouiPath = path
		ouiTable = nil
		ouiLoadedAt = time.Time{}
		ouiLastCheck = time.Time{}
	}
}

// VendorFor returns the IEEE-registered vendor name for a MAC address, or ""
// if unknown. The default lookup table is embedded in the binary; a configured
// oui_path still acts as an optional runtime override.
func VendorFor(mac string) string {
	normalized := NormalizeMAC(mac)
	if normalized == "" {
		return ""
	}
	prefix := strings.ReplaceAll(normalized, ":", "")
	if len(prefix) < 6 {
		return ""
	}
	prefix = prefix[:6]

	ouiMu.Lock()
	defer ouiMu.Unlock()
	maybeReloadOui()
	return ouiTable[prefix]
}

// maybeReloadOui reloads the cached table if the file's mtime has changed
// since the last load, checked at most once per ouiMtimeTTL. Caller must
// hold ouiMu.
func maybeReloadOui() {
	now := time.Now()
	if now.Sub(ouiLastCheck) < ouiMtimeTTL {
		return
	}
	ouiLastCheck = now

	info, err := os.Stat(ouiPath)
	if err != nil {
		ouiTable = nil
		if ouiPath == DefaultOuiPath {
			ouiTable = builtinOuiTable()
		}
		ouiLoadedAt = time.Time{}
		return
	}
	if info.ModTime().Equal(ouiLoadedAt) && ouiTable != nil {
		return
	}

	f, err := os.Open(ouiPath)
	if err != nil {
		ouiTable = nil
		ouiLoadedAt = time.Time{}
		return
	}
	defer f.Close()
	ouiTable = parseOuiFile(f)
	ouiLoadedAt = info.ModTime()
}

func builtinOuiTable() map[string]string {
	return ParseWiresharkManuf(strings.NewReader(builtinOuiManuf))
}

func parseOuiFile(r io.Reader) map[string]string {
	table := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		prefix := strings.ToLower(strings.TrimSpace(parts[0]))
		vendor := strings.TrimSpace(parts[1])
		if len(prefix) == 6 && isHex6(prefix) && vendor != "" {
			table[prefix] = vendor
		}
	}
	return table
}

func isHex6(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ParseWiresharkManuf parses the Wireshark "manuf" data file format
// (https://www.wireshark.org/download/automated/data/manuf) into a
// prefix->vendor map, keeping only 24-bit MA-L (OUI) entries - MA-M (/28)
// and MA-S (/36) entries carry a "/nn" suffix on the prefix field and are
// skipped, mirroring scripts/update_oui.sh's awk filter.
//
// Each kept line is "AA:BB:CC<TAB>ShortName<TAB>Long Description"; the short
// name is used, falling back to the long description when the short name is
// blank.
func ParseWiresharkManuf(r io.Reader) map[string]string {
	table := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		// Fields are padded with trailing spaces for alignment before the
		// next tab, e.g. "00:00:00         \tXerox       \tXerox Corp".
		prefixField := strings.TrimSpace(fields[0])
		if strings.Contains(prefixField, "/") {
			continue // MA-M/MA-S, not a 24-bit OUI
		}
		prefix := strings.ToLower(strings.ReplaceAll(prefixField, ":", ""))
		if len(prefix) != 6 || !isHex6(prefix) {
			continue
		}
		vendor := strings.TrimSpace(fields[1])
		if vendor == "" && len(fields) >= 3 {
			vendor = strings.TrimSpace(fields[2])
		}
		if vendor == "" {
			continue
		}
		table[prefix] = vendor
	}
	return table
}

// WriteOuiFile writes table to path in the oui.txt format VendorFor/
// parseOuiFile read, sorted by prefix, atomically (temp file + rename).
func WriteOuiFile(path, sourceURL string, table map[string]string) error {
	prefixes := make([]string, 0, len(table))
	for p := range table {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var b strings.Builder
	fmt.Fprintf(&b, "# OUI vendor lookup table - generated by `webfilter oui update`\n")
	fmt.Fprintf(&b, "# Source: %s\n", sourceURL)
	b.WriteString("# Format: <6-hex-lowercase-prefix><TAB><Vendor Name>\n")
	b.WriteString("# 24-bit MA-L entries only.\n\n")
	for _, p := range prefixes {
		fmt.Fprintf(&b, "%s\t%s\n", p, table[p])
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-oui-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
