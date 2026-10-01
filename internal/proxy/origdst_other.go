//go:build !linux

package proxy

import (
	"errors"
	"net"
)

// OriginalDestination is Linux-only: SO_ORIGINAL_DST is a netfilter conntrack
// facility with no equivalent elsewhere. The engine never binds a transparent
// listener off Linux, so this is only reachable from a test.
func OriginalDestination(conn net.Conn) (string, error) {
	return "", errors.New("transparent: original-destination recovery is only implemented on Linux")
}
