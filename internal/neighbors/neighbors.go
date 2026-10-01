// Package neighbors reads the OS neighbor table (ARP cache for IPv4, NDP /
// neighbor table for IPv6) so a client IP can be resolved to a MAC address,
// mirroring shared/neighbors.py. Used by the policy router's MAC-tier
// matching so a policy follows a device across DHCP IP changes.
//
// Hard limitation: the neighbor table only knows the MAC of hosts on the
// same layer-2 segment as this machine. A device behind a router resolves
// to the router's MAC. All reads are best-effort - any failure yields an
// empty result and callers fall back to IP matching.
//
// No user input ever reaches a subprocess: every command uses a fixed,
// hard-coded argument list.
package neighbors

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yjlion/llama-web-filter/internal/macutil"
)

// Entry is one resolved neighbor-table row.
type Entry struct {
	IP    string
	MAC   string
	Iface string
	// Vendor is the IEEE-registered OUI vendor name for MAC, populated from
	// the lookup table at ConfigureOUI's path, or the embedded fallback
	// (VendorFor) - "" if the prefix is unknown. Not needed for policy MAC
	// matching, only for the management API's neighbor-scan display.
	Vendor string
}

const ttl = 30 * time.Second

var (
	mu       sync.Mutex
	cache    map[string]string // normalized ip -> normalized mac
	cachedAt time.Time
)

// normalizeIP lowercases, strips a zone id, and unwraps IPv4-mapped IPv6
// (::ffff:192.168.1.5) to plain IPv4.
func normalizeIP(ip string) string {
	ip = strings.ToLower(strings.TrimSpace(ip))
	if idx := strings.IndexByte(ip, '%'); idx != -1 {
		ip = ip[:idx]
	}
	if strings.HasPrefix(ip, "::ffff:") && strings.Contains(ip, ".") {
		ip = ip[len("::ffff:"):]
	}
	return ip
}

func run(argv []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func rawScan() []Entry {
	switch {
	case runtime.GOOS == "linux":
		return scanLinux()
	case runtime.GOOS == "windows":
		return scanWindows()
	case runtime.GOOS == "darwin" || strings.Contains(runtime.GOOS, "bsd"):
		return scanBSD()
	default:
		return nil
	}
}

func scanLinux() []Entry {
	text := run([]string{"ip", "neigh", "show"})
	if strings.TrimSpace(text) != "" {
		if rows := parseLinuxIPNeigh(text); len(rows) > 0 {
			return rows
		}
	}
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}
	return parseProcNetARP(string(data))
}

func scanWindows() []Entry {
	rows := parseWindowsARP(run([]string{"arp", "-a"}))
	rows = append(rows, parseWindowsNetsh(run([]string{"netsh", "interface", "ipv6", "show", "neighbors"}))...)
	return rows
}

func scanBSD() []Entry {
	rows := parseBSDARP(run([]string{"arp", "-an"}))
	rows = append(rows, parseBSDNDP(run([]string{"ndp", "-an"}))...)
	return rows
}

// isUnicast is true for an individually-addressed (unicast) MAC. Excludes
// broadcast (ff:ff:...) and multicast (LSB of the first octet set, e.g.
// 01:00:5e, 33:33) entries, which never identify a single device.
func isUnicast(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var first byte
	for _, c := range mac[:2] {
		first <<= 4
		switch {
		case c >= '0' && c <= '9':
			first |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			first |= byte(c-'a') + 10
		default:
			return false
		}
	}
	return first&0x01 == 0
}

// Scan returns the current neighbor table, de-duplicated by MAC and sorted
// by IP. Best-effort: returns nil on any platform/tooling failure.
func Scan() []Entry {
	seen := make(map[string]Entry)
	order := make([]string, 0)
	for _, e := range rawScan() {
		if e.MAC == "" || !isUnicast(e.MAC) {
			continue
		}
		if _, ok := seen[e.MAC]; !ok {
			seen[e.MAC] = e
			order = append(order, e.MAC)
		}
	}
	out := make([]Entry, 0, len(order))
	for _, mac := range order {
		e := seen[mac]
		e.Vendor = VendorFor(e.MAC)
		out = append(out, e)
	}
	sortEntriesByIP(out)
	return out
}

func sortEntriesByIP(entries []Entry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j-1].IP > entries[j].IP; j-- {
			entries[j-1], entries[j] = entries[j], entries[j-1]
		}
	}
}

func refreshCache() {
	rows := rawScan()
	next := make(map[string]string, len(rows))
	for _, e := range rows {
		if e.IP != "" && e.MAC != "" {
			next[e.IP] = e.MAC
		}
	}
	cache = next
	cachedAt = time.Now()
}

// Lookup resolves a client IP to a normalized MAC, or "" if unknown. The
// neighbor table is cached for 30s so a busy proxy doesn't shell out on
// every request.
func Lookup(ip string) string {
	if ip == "" {
		return ""
	}
	key := normalizeIP(ip)
	mu.Lock()
	defer mu.Unlock()
	if time.Since(cachedAt) > ttl || cache == nil {
		refreshCache()
	}
	return cache[key]
}

// NormalizeMAC canonicalizes a MAC to lowercase colon-separated form,
// delegating to macutil.Normalize (shared with policy source_macs
// validation).
func NormalizeMAC(v string) string {
	return macutil.Normalize(v)
}
