package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
)

// SOCKS5 protocol constants (RFC 1928) and the username/password auth
// sub-negotiation (RFC 1929). This engine implements CONNECT (the full MITM
// tunnel path) and a DNS-only UDP ASSOCIATE relay (see socks5_udp.go, for the
// Android TUN path); BIND is rejected with "command not supported".
const (
	socksVersion = 0x05 // RFC 1928 version octet
	authVersion  = 0x01 // RFC 1929 auth sub-negotiation version octet

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	authSuccess = 0x00
	authFailure = 0x01

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded            = 0x00
	repGeneralFailure       = 0x01
	repNotAllowed           = 0x02 // connection not allowed by ruleset
	repConnectionRefused    = 0x05
	repCommandNotSupported  = 0x07
	repAddrTypeNotSupported = 0x08
)

var errUnsupportedAddrType = errors.New("socks5: unsupported address type")

// serveSocksConn handles one accepted SOCKS5 client connection: the RFC 1928
// greeting + method selection, optional RFC 1929 username/password auth, and
// the CONNECT request, then hands the tunnel off to the shared handleTunnel
// path (blind-splice or MITM) - the same interception and addon pipeline the
// HTTP CONNECT path uses. Only CONNECT is supported.
func (e *Engine) serveSocksConn(conn net.Conn, connID uint64) {
	defer conn.Close()
	clientIP := hostOnlyOf(conn.RemoteAddr().String())
	proxySockName := hostOnlyOf(conn.LocalAddr().String())

	reader := bufio.NewReader(conn)

	// Greeting: VER, NMETHODS, METHODS[NMETHODS].
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(reader, greeting); err != nil {
		return
	}
	if greeting[0] != socksVersion {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	var gate SocksAuthGate
	if e.Pipeline != nil {
		gate = e.Pipeline.SocksAuthGateAddon()
	}
	if gate != nil {
		defer gate.ClientDisconnected(connID)
	}

	if gate != nil && gate.SocksAuthRequired() {
		if bytes.IndexByte(methods, methodUserPass) < 0 {
			writeMethodSelection(conn, methodNoAcceptable)
			return
		}
		if err := writeMethodSelection(conn, methodUserPass); err != nil {
			return
		}
		user, pass, err := readUserPassAuth(reader)
		if err != nil {
			return
		}
		if !gate.AuthorizeSocks(user, pass, connID) {
			writeAuthStatus(conn, authFailure)
			return
		}
		if err := writeAuthStatus(conn, authSuccess); err != nil {
			return
		}
	} else {
		if bytes.IndexByte(methods, methodNoAuth) < 0 {
			writeMethodSelection(conn, methodNoAcceptable)
			return
		}
		if err := writeMethodSelection(conn, methodNoAuth); err != nil {
			return
		}
		// Mark the connection authorized (a no-op when auth is disabled) so
		// the request-phase gate treats tunneled requests as authenticated,
		// mirroring the CONNECT path.
		if gate != nil {
			gate.AuthorizeSocks("", "", connID)
		}
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != socksVersion {
		return
	}
	cmd, atyp := reqHeader[1], reqHeader[3]

	host, err := readSocksAddr(reader, atyp)
	if err != nil {
		writeSocksReply(conn, repAddrTypeNotSupported)
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes))

	switch cmd {
	case cmdConnect:
		// Handled below via the shared tunnel path.
	case cmdUDPAssociate:
		// UDP ASSOCIATE's DST.ADDR/DST.PORT (read above) are the address the
		// client expects to send from; RFC 1928 lets us ignore them. The relay
		// exists for the TUN paths — see serveSocksUDPAssociate.
		e.serveSocksUDPAssociate(conn, clientIP)
		return
	default: // cmdBind and anything else
		writeSocksReply(conn, repCommandNotSupported)
		return
	}

	targetHost := net.JoinHostPort(host, strconv.Itoa(port))

	// The SOCKS readiness signal is a reply message: success once the tunnel
	// is ready, or a mapped failure code if the upstream dial failed on the
	// blind-splice path.
	ready := func(dialErr error) error {
		if dialErr != nil {
			writeSocksReply(conn, socksReplyForDialErr(dialErr))
			return dialErr
		}
		return writeSocksReply(conn, repSucceeded)
	}
	e.handleTunnel(conn, reader, targetHost, host, connID, clientIP, proxySockName, ready)
}

// readSocksAddr reads a SOCKS5 address of the given ATYP, returning it as a
// host string (dotted-quad / bracketless IPv6 literal / domain name). Domain
// names are preserved verbatim so downstream SNI and MITM see the hostname,
// exactly like the CONNECT target host.
func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypIPv6:
		b := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(r, lenByte); err != nil {
			return "", err
		}
		b := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", errUnsupportedAddrType
	}
}

// readUserPassAuth reads an RFC 1929 username/password sub-negotiation
// request: VER, ULEN, UNAME, PLEN, PASSWD.
func readUserPassAuth(r io.Reader) (username, password string, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", "", err
	}
	if header[0] != authVersion {
		return "", "", errors.New("socks5: unsupported auth version")
	}
	uname := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, uname); err != nil {
		return "", "", err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(r, plen); err != nil {
		return "", "", err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(r, passwd); err != nil {
		return "", "", err
	}
	return string(uname), string(passwd), nil
}

// socksReplyForDialErr maps a tunnel failure to a SOCKS5 reply code: a policy
// refusal from the connection gate reports "not allowed by ruleset", and an
// upstream dial error reports a refused connection where possible.
func socksReplyForDialErr(err error) byte {
	if errors.Is(err, ErrBlockedByPolicy) {
		return repNotAllowed
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return repConnectionRefused
	}
	return repGeneralFailure
}

func writeMethodSelection(w io.Writer, method byte) error {
	_, err := w.Write([]byte{socksVersion, method})
	return err
}

func writeAuthStatus(w io.Writer, status byte) error {
	_, err := w.Write([]byte{authVersion, status})
	return err
}

// writeSocksReply writes a SOCKS5 reply with the given reply code and a
// zeroed IPv4 BND.ADDR/BND.PORT (clients ignore the bound address for an
// outbound CONNECT).
func writeSocksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
