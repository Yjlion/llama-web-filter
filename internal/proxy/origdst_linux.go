//go:build linux

package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ip6tSOOriginalDst is the IPv6 counterpart of unix.SO_ORIGINAL_DST. It has
// the same numeric value and lives at IPPROTO_IPV6; x/sys/unix does not export
// a name for it at the version this module pins, so it is spelled out here.
const ip6tSOOriginalDst = 80

// sockaddrIn6Size is the largest reply SO_ORIGINAL_DST can produce
// (sockaddr_in6); a sockaddr_in reply simply fills fewer of the bytes.
const sockaddrIn6Size = 28

// OriginalDestination recovers the address a REDIRECTed connection was
// *originally* headed for, before netfilter rewrote it to this listener.
//
// A transparent proxy has no handshake to learn its target from: the client
// believes it opened a socket straight to the origin server, so the only
// record of where it meant to go is the conntrack entry the NAT created.
// SO_ORIGINAL_DST reads that back.
func OriginalDestination(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("transparent: connection is %T, not *net.TCPConn", conn)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr string
	var soErr error
	if err := raw.Control(func(fd uintptr) {
		addr, soErr = originalDstFromFD(int(fd))
	}); err != nil {
		return "", err
	}
	return addr, soErr
}

// originalDstFromFD asks the kernel for the pre-NAT destination and decodes the
// raw sockaddr it returns. IPv4 is tried first because REDIRECT produces it for
// nearly all traffic and the v6 option fails outright on a v4 socket.
//
// The raw syscall is deliberate: the reply is a sockaddr, and x/sys/unix has no
// getsockopt accessor of that shape - the usual workaround borrows
// GetsockoptIPv6Mreq for its buffer size, which is big enough for sockaddr_in
// but not sockaddr_in6, and silently truncates IPv6 results.
func originalDstFromFD(fd int) (string, error) {
	var buf [sockaddrIn6Size]byte

	for _, opt := range []struct{ level, name int }{
		{unix.IPPROTO_IP, unix.SO_ORIGINAL_DST},
		{unix.IPPROTO_IPV6, ip6tSOOriginalDst},
	} {
		size := uint32(len(buf))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
			uintptr(fd), uintptr(opt.level), uintptr(opt.name),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			continue
		}
		if addr, ok := decodeSockaddr(buf[:size]); ok {
			return addr, nil
		}
	}
	return "", fmt.Errorf("transparent: SO_ORIGINAL_DST returned no usable address " +
		"(is this connection actually REDIRECTed?)")
}

// decodeSockaddr reads a kernel sockaddr_in / sockaddr_in6. The port is network
// byte order in both; the family tells them apart.
func decodeSockaddr(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	family := binary.LittleEndian.Uint16(b[0:2]) // sa_family_t is host order
	port := binary.BigEndian.Uint16(b[2:4])
	switch family {
	case unix.AF_INET:
		ip := net.IPv4(b[4], b[5], b[6], b[7])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), true
	case unix.AF_INET6:
		if len(b) < 24 {
			return "", false
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, b[8:24])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), true
	}
	return "", false
}
