// Package macutil normalizes MAC address strings to a canonical form,
// shared by policy source_macs validation and ARP/NDP neighbor scanning.
package macutil

import "strings"

// Normalize canonicalizes a MAC address to lowercase colon-separated form
// (aa:bb:cc:dd:ee:ff). It accepts ':'/'-' separated octets, Cisco dotted
// form (aabb.ccdd.eeff), and bare hex (aabbccddeeff). Returns "" if the
// input isn't exactly 12 hex digits once separators are stripped.
func Normalize(s string) string {
	var hex strings.Builder
	for _, r := range s {
		switch {
		case r == ':' || r == '-' || r == '.':
			continue
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r >= 'A' && r <= 'F':
			hex.WriteRune(r - 'A' + 'a')
		default:
			return ""
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}
