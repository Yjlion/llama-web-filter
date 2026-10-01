package icap

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Encapsulated entity names (RFC 3507 §4.4.1). An ICAP message body is a
// concatenation of these parts; the Encapsulated header is the index that
// says where each one starts.
const (
	entReqHdr   = "req-hdr"
	entResHdr   = "res-hdr"
	entReqBody  = "req-body"
	entResBody  = "res-body"
	entOptBody  = "opt-body"
	entNullBody = "null-body"
)

// encapsulatedEntry is one "name=offset" pair from an Encapsulated header.
type encapsulatedEntry struct {
	Name   string
	Offset int
}

// isBody reports whether the entry names a body part, which is always last
// and is the only part transferred chunked.
func (e encapsulatedEntry) isBody() bool {
	switch e.Name {
	case entReqBody, entResBody, entOptBody, entNullBody:
		return true
	}
	return false
}

// parseEncapsulated parses an Encapsulated header value into its entries,
// sorted by offset. The sort matters: the parts arrive in offset order and
// each header part's length is the distance to the next offset, so a client
// that lists them out of order (legal - the header is a set) would otherwise
// produce negative lengths.
func parseEncapsulated(value string) ([]encapsulatedEntry, error) {
	var entries []encapsulatedEntry
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, fmt.Errorf("icap: malformed Encapsulated entry %q", part)
		}
		name := strings.ToLower(strings.TrimSpace(part[:eq]))
		offset, err := strconv.Atoi(strings.TrimSpace(part[eq+1:]))
		if err != nil || offset < 0 {
			return nil, fmt.Errorf("icap: malformed Encapsulated offset in %q", part)
		}
		entries = append(entries, encapsulatedEntry{Name: name, Offset: offset})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Offset < entries[j].Offset })
	return entries, nil
}

// formatEncapsulated renders entries back into a header value.
func formatEncapsulated(entries []encapsulatedEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%s=%d", e.Name, e.Offset))
	}
	return strings.Join(parts, ", ")
}
