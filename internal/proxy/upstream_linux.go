//go:build linux

package proxy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// controlUpstreamSocket stamps the engine's egress mark on a socket before it
// is connected or bound, so the `fwmark ... lookup main` rule that
// internal/tun2socks installs keeps this traffic out of the TUN device.
//
// Android reaches this code too (mobile/ links the proxy engine), and that is
// harmless: the mark is only ever non-zero on a host where the desktop
// tun2socks supervisor configured routing, which the VpnService path never
// does.
func controlUpstreamSocket(network, address string, c syscall.RawConn) error {
	mark := egressMark.Load()
	if mark == 0 {
		return nil
	}
	var setErr error
	if err := c.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	if setErr != nil {
		warnMarkUnavailable(setErr)
	}
	// Deliberately not returned as an error: an unmarked socket still works.
	return nil
}
