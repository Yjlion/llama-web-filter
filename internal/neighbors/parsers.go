package neighbors

import (
	"regexp"
	"strings"
)

// Per-platform parsers - pure functions fed captured command output, never
// running a process themselves - ported line-for-line from
// shared/neighbors.py's regexes.

var linuxNeighRE = regexp.MustCompile(`^(\S+)\s+dev\s+(\S+)\s+.*?lladdr\s+([0-9a-fA-F:]{17})`)

// parseLinuxIPNeigh parses `ip neigh show` output. Lines look like:
// "192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE". Entries
// without an lladdr (FAILED / INCOMPLETE) are skipped.
func parseLinuxIPNeigh(text string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "lladdr") {
			continue
		}
		m := linuxNeighRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mac := macutilNormalize(m[3])
		if mac == "" {
			continue
		}
		out = append(out, Entry{IP: normalizeIP(m[1]), MAC: mac, Iface: m[2]})
	}
	return out
}

var procArpRE = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+([0-9a-fA-F:]{17})\s+\S*\s+(\S+)`)

// parseProcNetARP parses /proc/net/arp (IPv4 only), a fallback when `ip` is
// absent. Columns: IP address / HW type / Flags / HW address / Mask /
// Device. The all-zero MAC marks an incomplete entry and is skipped.
func parseProcNetARP(text string) []Entry {
	lines := strings.Split(text, "\n")
	var out []Entry
	for _, line := range lines[min(1, len(lines)):] { // skip header
		m := procArpRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		mac := macutilNormalize(m[2])
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, Entry{IP: normalizeIP(m[1]), MAC: mac, Iface: m[3]})
	}
	return out
}

var winArpRE = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s`)

// parseWindowsARP parses Windows `arp -a` output (IPv4). MACs use '-'
// separators.
func parseWindowsARP(text string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		m := winArpRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		mac := macutilNormalize(m[2])
		if mac == "" {
			continue
		}
		out = append(out, Entry{IP: normalizeIP(m[1]), MAC: mac})
	}
	return out
}

var winNetshRE = regexp.MustCompile(`^([0-9a-fA-F:]+:[0-9a-fA-F:]*|\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s`)

// parseWindowsNetsh parses `netsh interface ipv6 show neighbors` output
// (IPv6 neighbors).
func parseWindowsNetsh(text string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		m := winNetshRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		mac := macutilNormalize(m[2])
		if mac == "" {
			continue
		}
		out = append(out, Entry{IP: normalizeIP(m[1]), MAC: mac})
	}
	return out
}

var bsdArpRE = regexp.MustCompile(`\(([0-9a-fA-F:.]+)\)\s+at\s+([0-9a-fA-F:]+)(?:\s+on\s+(\S+))?`)

// parseBSDARP parses macOS/BSD `arp -an` output (IPv4):
// "? (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]".
// Incomplete entries show "(incomplete)" for the MAC and are skipped.
func parseBSDARP(text string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		m := bsdArpRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mac := macutilNormalize(m[2])
		if mac == "" {
			continue
		}
		out = append(out, Entry{IP: normalizeIP(m[1]), MAC: mac, Iface: m[3]})
	}
	return out
}

var bsdNdpRE = regexp.MustCompile(`^([0-9a-fA-F:][0-9a-fA-F:.%a-zA-Z0-9]*:[0-9a-fA-F:.%a-zA-Z0-9]*)\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s+(\S+)`)

// parseBSDNDP parses macOS/BSD `ndp -an` output (IPv6 neighbors):
// "fe80::1%en0  aa:bb:cc:dd:ee:02  en0  23s  R" - the header row and
// "(incomplete)" entries don't match the MAC column and are skipped.
func parseBSDNDP(text string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		m := bsdNdpRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		mac := macutilNormalize(m[2])
		if mac == "" {
			continue
		}
		out = append(out, Entry{IP: normalizeIP(m[1]), MAC: mac, Iface: m[3]})
	}
	return out
}

// macutilNormalize wraps macutil.Normalize under the local name the ported
// Python code used (normalize_mac), purely so the parser bodies above read
// the same as their Python originals.
func macutilNormalize(v string) string {
	return NormalizeMAC(v)
}
