//go:build !linux

package proxy

import "syscall"

// controlUpstreamSocket is a no-op off Linux. SO_MARK is a Linux concept, and
// TUN capture on Windows keeps the engine's own traffic out of the tunnel a
// different way (the adapter's route metric), so there is nothing to stamp.
func controlUpstreamSocket(network, address string, c syscall.RawConn) error {
	return nil
}
