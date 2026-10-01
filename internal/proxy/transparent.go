package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
)

// serveTransparentConn handles a connection netfilter REDIRECTed to this
// listener. Unlike CONNECT and SOCKS there is no handshake: the client believes
// it is already talking to the origin server, so the front-end's whole job is
// to work out where that was and hand the connection to the shared tunnel seam.
//
// This is what makes the gateway use case work. The client's source address is
// preserved by REDIRECT (only the destination is rewritten), so
// Runtime.GetPolicy sees the real LAN client and the per-client policy tiers -
// MAC/IP/CIDR - apply exactly as they do for a configured proxy client.
func (e *Engine) serveTransparentConn(conn net.Conn, connID uint64) {
	defer conn.Close()
	clientIP := hostOnlyOf(conn.RemoteAddr().String())
	proxySockName := hostOnlyOf(conn.LocalAddr().String())

	origDst, err := OriginalDestination(conn)
	if err != nil {
		slog.Debug("transparent: no original destination", "client", clientIP, "err", err)
		return
	}
	// A connection made straight to the transparent port was never redirected,
	// so its "original" destination is this listener. Proxying it would dial
	// ourselves, forever.
	if origDst == conn.LocalAddr().String() {
		slog.Debug("transparent: refusing a direct connection to the transparent listener",
			"client", clientIP, "addr", origDst)
		return
	}

	reader := bufio.NewReader(conn)

	// Every host-scoped decision in the engine - MITM exclusion, the
	// connection-level host gate, category lookups - keys on a *name*, and
	// transparent capture only recovers an address. Read the name out of the
	// traffic itself before handing over: the TLS SNI, or the Host header for
	// plaintext. Without this, a gateway would silently stop honouring every
	// hostname-based exclusion, because every target would look like an IP.
	hostOnly, _, splitErr := net.SplitHostPort(origDst)
	if splitErr != nil {
		hostOnly = origDst
	}
	if name := peekRequestedHost(reader); name != "" {
		hostOnly = name
	}

	// Nothing to signal: the client already has what it thinks is an
	// end-to-end connection, so a readiness reply would be injected bytes. A
	// failed upstream dial can only be reported by closing.
	ready := func(dialErr error) error { return dialErr }

	e.handleTunnel(conn, reader, origDst, hostOnly, connID, clientIP, proxySockName, ready)
}

// peekTransparentBytes bounds how far into the first client write the hostname
// sniff will look. A ClientHello with a long cipher list and ALPN still fits
// comfortably, and so does any realistic HTTP request head.
const peekTransparentBytes = 4096

// peekRequestedHost reads the hostname the client is asking for without
// consuming anything: SNI for TLS, the Host header for plaintext HTTP. Returns
// "" when it cannot tell, which leaves the caller on the recovered IP.
func peekRequestedHost(r *bufio.Reader) string {
	first, err := r.Peek(1)
	if err != nil {
		return ""
	}
	// Peek as much as is already buffered rather than insisting on the full
	// window: Peek blocks until it has n bytes, and a short first write (a
	// small ClientHello, a pipelined GET) would otherwise stall until the
	// client sent more, which it is waiting on us to allow.
	buf, err := peekUpTo(r, peekTransparentBytes)
	if err != nil || len(buf) == 0 {
		return ""
	}
	if first[0] == 0x16 {
		return sniFromClientHello(buf)
	}
	return hostFromHTTPHead(buf)
}

// peekUpTo returns up to n buffered bytes, shrinking the request until Peek can
// satisfy it from what has already arrived.
func peekUpTo(r *bufio.Reader, n int) ([]byte, error) {
	if _, err := r.Peek(1); err != nil {
		return nil, err
	}
	if avail := r.Buffered(); avail < n {
		n = avail
	}
	return r.Peek(n)
}

// hostFromHTTPHead pulls the Host header out of a request head.
func hostFromHTTPHead(b []byte) string {
	head, _, _ := bytes.Cut(b, []byte("\r\n\r\n"))
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found || !strings.EqualFold(string(bytes.TrimSpace(name)), "host") {
			continue
		}
		host := strings.TrimSpace(string(value))
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
		return host
	}
	return ""
}

// sniFromClientHello extracts server_name from a TLS ClientHello record.
//
// Written out by hand rather than borrowed from crypto/tls because every
// stdlib route to the SNI (tls.Server + GetCertificate) consumes the bytes and
// completes a handshake, and this has to run *before* the bypass decision that
// determines whether a handshake should happen at all. Returns "" for anything
// it does not fully understand - a wrong guess here would misroute policy, so
// the fallback to the recovered IP is the safer answer.
func sniFromClientHello(b []byte) string {
	// TLSPlaintext: type(1) version(2) length(2), then the handshake message.
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	rec := b[5:]
	if n := int(binary.BigEndian.Uint16(b[3:5])); n < len(rec) {
		rec = rec[:n]
	}
	// Handshake: msg_type(1) length(3) — msg_type 1 is client_hello.
	if len(rec) < 4 || rec[0] != 0x01 {
		return ""
	}
	body := rec[4:]

	// client_version(2) random(32)
	if len(body) < 34 {
		return ""
	}
	body = body[34:]
	// session_id, cipher_suites, compression_methods: each length-prefixed.
	var ok bool
	if body, ok = skipVector(body, 1); !ok {
		return ""
	}
	if body, ok = skipVector(body, 2); !ok {
		return ""
	}
	if body, ok = skipVector(body, 1); !ok {
		return ""
	}
	// extensions<2>
	if len(body) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(body[0:2]))
	body = body[2:]
	if extLen > len(body) {
		extLen = len(body)
	}
	ext := body[:extLen]

	for len(ext) >= 4 {
		extType := binary.BigEndian.Uint16(ext[0:2])
		dataLen := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if dataLen > len(ext) {
			return ""
		}
		if extType == 0x0000 { // server_name
			return firstHostName(ext[:dataLen])
		}
		ext = ext[dataLen:]
	}
	return ""
}

// firstHostName reads the first host_name entry of a server_name extension:
// list_length(2), then entries of name_type(1) length(2) value.
func firstHostName(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(d[0:2]))
	d = d[2:]
	if listLen > len(d) {
		listLen = len(d)
	}
	d = d[:listLen]
	for len(d) >= 3 {
		nameType := d[0]
		n := int(binary.BigEndian.Uint16(d[1:3]))
		d = d[3:]
		if n > len(d) {
			return ""
		}
		if nameType == 0 { // host_name
			return string(d[:n])
		}
		d = d[n:]
	}
	return ""
}

// skipVector steps over a TLS vector whose length is held in the next lenBytes
// bytes.
func skipVector(b []byte, lenBytes int) ([]byte, bool) {
	if len(b) < lenBytes {
		return nil, false
	}
	n := 0
	for _, c := range b[:lenBytes] {
		n = n<<8 | int(c)
	}
	b = b[lenBytes:]
	if n > len(b) {
		return nil, false
	}
	return b[n:], true
}
