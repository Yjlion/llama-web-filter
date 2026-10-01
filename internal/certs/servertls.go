package certs

import (
	"crypto/tls"
	"net"
)

// ServerTLSConfig builds the server-side tls.Config for an endpoint that
// presents CA-minted leaves: TLS-wrapped proxy listeners (https@ / tls@ /
// tls+<base>@) and, when mgmt_tls is on, the management server.
//
// The non-obvious part is the SNI fallback. A client pointed at an
// IP-literal endpoint sends no SNI at all, so GetCertificate has nothing to
// key on; falling back to the address the connection actually landed on
// means hostname/IP verification against the issued leaf still passes.
// fallbackName is the last resort when even that is unavailable.
//
// Only http/1.1 is advertised, matching the rest of the engine's no-h2
// stance.
//
// This lives here rather than in internal/proxy so the proxy and the
// management server cannot drift apart on the SNI-less rule - it is the kind
// of detail that gets reimplemented slightly differently the second time.
func ServerTLSConfig(li *LeafIssuer, fallbackName string) *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" && hello.Conn != nil {
				name = hostOnly(hello.Conn.LocalAddr().String())
			}
			if name == "" {
				name = fallbackName
			}
			return li.CertificateFor(name)
		},
		NextProtos: []string{"http/1.1"},
	}
}

// hostOnly strips the port from a "host:port" address, returning addr
// unchanged when it has none.
func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
