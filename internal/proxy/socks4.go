package proxy

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
)

// SOCKS4 / SOCKS4a protocol constants (there is no formal RFC; this follows
// the de-facto spec). This engine implements CONNECT only - the same MITM
// tunnel path CONNECT and SOCKS5 use; BIND and anything else are rejected.
const (
	socks4Version = 0x04

	socks4CmdConnect = 0x01

	socks4Granted  = 0x5A // request granted (90)
	socks4Rejected = 0x5B // request rejected or failed (91)
)

// serveSocks4Conn handles one accepted SOCKS4/SOCKS4a client connection: the
// CONNECT request (VN, CD, DSTPORT, DSTIP, USERID\0, and - for SOCKS4a, when
// DSTIP is 0.0.0.x - a trailing hostname\0), then hands the tunnel off to the
// shared handleTunnel path (blind-splice or MITM), exactly like the SOCKS5 and
// HTTP CONNECT handlers. SOCKS4 has no password authentication, so a proxy
// configured to require credentials rejects SOCKS4 clients outright.
func (e *Engine) serveSocks4Conn(conn net.Conn, connID uint64) {
	defer conn.Close()
	clientIP := hostOnlyOf(conn.RemoteAddr().String())
	proxySockName := hostOnlyOf(conn.LocalAddr().String())

	reader := bufio.NewReader(conn)

	// Fixed 8-byte header: VN, CD, DSTPORT(2), DSTIP(4).
	header := make([]byte, 8)
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	if header[0] != socks4Version {
		return
	}
	cmd := header[1]
	port := int(binary.BigEndian.Uint16(header[2:4]))

	// USERID: bytes up to and including a NUL terminator. Discarded - SOCKS4
	// identifies by userid, but this proxy gates on client IP, not userid.
	if _, err := reader.ReadBytes(0x00); err != nil {
		return
	}

	// SOCKS4a: a DSTIP of 0.0.0.x (x != 0) signals that a hostname, NUL
	// terminated, follows the userid; the real target is that name.
	host := net.IP(header[4:8]).String()
	if header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] != 0 {
		domain, err := reader.ReadBytes(0x00)
		if err != nil {
			return
		}
		host = string(domain[:len(domain)-1]) // strip the NUL terminator
	}

	var gate SocksAuthGate
	if e.Pipeline != nil {
		gate = e.Pipeline.SocksAuthGateAddon()
	}
	if gate != nil {
		defer gate.ClientDisconnected(connID)
	}
	if gate != nil && gate.SocksAuthRequired() {
		// No credential channel exists in SOCKS4; refuse rather than admit an
		// unauthenticated client on an auth-required proxy.
		_ = writeSocks4Reply(conn, socks4Rejected)
		return
	}
	if gate != nil {
		// Mark authorized (no-op when auth is disabled) so the request-phase
		// gate treats tunneled requests as authenticated, mirroring SOCKS5.
		gate.AuthorizeSocks("", "", connID)
	}

	if cmd != socks4CmdConnect {
		_ = writeSocks4Reply(conn, socks4Rejected)
		return
	}

	targetHost := net.JoinHostPort(host, strconv.Itoa(port))
	ready := func(dialErr error) error {
		if dialErr != nil {
			_ = writeSocks4Reply(conn, socks4Rejected)
			return dialErr
		}
		return writeSocks4Reply(conn, socks4Granted)
	}
	e.handleTunnel(conn, reader, targetHost, host, connID, clientIP, proxySockName, ready)
}

// writeSocks4Reply writes an 8-byte SOCKS4 reply: a zero version octet, the
// result code, and a zeroed DSTPORT/DSTIP (clients ignore both for CONNECT).
func writeSocks4Reply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{0x00, code, 0, 0, 0, 0, 0, 0})
	return err
}
