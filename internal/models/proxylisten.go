package models

import (
	"strconv"
	"strings"
)

// KnownProxyModes are the base proxy_listen mode prefixes this port
// recognizes (the protocol spoken on the listener). WireGuard is deliberately
// excluded (out of scope for this port per the project plan) but ParseListen
// still recognizes the literal string "wireguard" as a known-but-unsupported
// mode rather than misparsing it, so a settings.json carried over from the
// Python original doesn't error out - the caller decides whether to skip
// starting a listener for it.
//
// On top of these base modes, a listener can be wrapped in TLS. Four tokens
// express that: the general composite prefix "tls+<base>" (e.g.
// "tls+regular", "tls+socks5", "tls+socks4"), plus three friendly aliases -
// "https" for "tls+regular" (an HTTP forward proxy served over TLS, i.e. the
// browser's "Secure Web Proxy" / PAC HTTPS directive), "tls" for
// "tls+socks5" (a SOCKS5 proxy served over TLS), and "icaps" for "tls+icap"
// (the ICAP adaptation service over TLS, which is the scheme name ICAP
// clients use for it). See ParseListenSpec.
var KnownProxyModes = []string{
	"regular", "transparent", "socks4", "socks5", "icap", "upstream", "reverse", "dns", "tun", "local",
}

// unsupportedProxyModes are recognized but not started by this port.
var unsupportedProxyModes = map[string]bool{"wireguard": true}

func isKnownMode(m string) bool {
	for _, k := range KnownProxyModes {
		if k == m {
			return true
		}
	}
	return unsupportedProxyModes[m]
}

// resolveModeToken maps the token before the "@" in a proxy_listen entry to a
// base mode and whether the listener is TLS-wrapped. ok is false for tokens
// that are not a recognized mode (the caller then treats the whole entry as a
// bare host:port). See KnownProxyModes for the TLS token vocabulary.
func resolveModeToken(token string) (base string, tls, ok bool) {
	switch token {
	case "https":
		return "regular", true, true
	case "tls":
		return "socks5", true, true
	case "icaps":
		return "icap", true, true
	}
	if rest, found := strings.CutPrefix(token, "tls+"); found {
		if isKnownMode(rest) {
			return rest, true, true
		}
		return "", false, false
	}
	if isKnownMode(token) {
		return token, false, true
	}
	return "", false, false
}

// SplitHostPort parses a "host:port" string, supporting plain IPv4/hostname
// (host:port), bracketed IPv6 ([::1]:port), and - for backward
// compatibility with settings.json files carried over from the Python
// original, which historically emitted IPv6 listen hosts without brackets
// - bare IPv6 (::1:port, port taken after the last colon). Returns port=0
// if unparseable.
func SplitHostPort(entry string) (host string, port int) {
	entry = trimSpace(entry)
	if entry == "" {
		return "", 0
	}
	if strings.HasPrefix(entry, "[") {
		// Bracketed IPv6: [addr]:port
		end := strings.Index(entry, "]")
		if end == -1 {
			return entry, 0
		}
		host = entry[1:end]
		rest := entry[end+1:]
		if strings.HasPrefix(rest, ":") {
			port, _ = strconv.Atoi(rest[1:])
		}
		return host, port
	}
	if strings.Count(entry, ":") > 1 {
		// Bare (unbracketed) IPv6 with a trailing :port - split on the
		// last colon, everything before it is the address.
		idx := strings.LastIndex(entry, ":")
		host = entry[:idx]
		port, _ = strconv.Atoi(entry[idx+1:])
		return host, port
	}
	// Plain host:port (IPv4 or hostname).
	idx := strings.LastIndex(entry, ":")
	if idx == -1 {
		return entry, 0
	}
	host = entry[:idx]
	port, _ = strconv.Atoi(entry[idx+1:])
	return host, port
}

// ProxyListenSpec is a fully-parsed proxy_listen entry: the base protocol
// (Mode), whether the listener is TLS-wrapped (TLS), and the bind address.
type ProxyListenSpec struct {
	Mode string // base protocol: regular, socks4, socks5, transparent, ...
	TLS  bool   // listener wrapped in TLS (https@ / tls@ / tls+<base>@)
	Host string
	Port int
}

// ParseListenSpec parses a proxy_listen entry into its base mode, TLS flag,
// and bind address. Entries are a bare "host:port" (mode "regular"), a
// "mode@host:port" (where mode may be a TLS token - see KnownProxyModes), or
// a bare "tun"/"local" (no address). Mirrors the Python original's
// parse_listen(), extended with the TLS-wrapping token vocabulary.
func ParseListenSpec(entry string) ProxyListenSpec {
	entry = trimSpace(entry)
	spec := ProxyListenSpec{Mode: "regular"}
	if entry == "" {
		return spec
	}
	if at := strings.Index(entry, "@"); at != -1 {
		if base, tls, ok := resolveModeToken(entry[:at]); ok {
			spec.Mode, spec.TLS = base, tls
			if rest := entry[at+1:]; rest != "" {
				spec.Host, spec.Port = SplitHostPort(rest)
			}
			return spec
		}
	}
	if entry == "tun" || entry == "local" {
		spec.Mode = entry
		return spec
	}
	spec.Host, spec.Port = SplitHostPort(entry)
	return spec
}

// ParseListen parses a proxy_listen entry into (mode, host, port), where mode
// is the base protocol. It discards the TLS flag; callers that must
// distinguish a TLS-wrapped listener (e.g. PAC, which can only point at a
// plaintext HTTP proxy) use ParseListenSpec instead.
func ParseListen(entry string) (mode, host string, port int) {
	spec := ParseListenSpec(entry)
	return spec.Mode, spec.Host, spec.Port
}
