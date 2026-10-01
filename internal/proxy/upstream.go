package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Every outbound connection the filter makes - upstream fetches, blind
// tunnels, DoH resolutions, relayed UDP - goes through the helpers in this
// file rather than calling net.Dial directly. There used to be eight
// independent dial sites, which was fine until TUN capture arrived: once
// capture installs a default route through the TUN device, the engine's own
// upstream sockets follow it straight back into tun2socks, which hands them to
// the engine's SOCKS5 listener, which dials upstream again. That is an
// unbounded loop, and the only way out is for the engine's own traffic to be
// distinguishable from everybody else's.
//
// On Linux it is distinguished with a firewall mark (SO_MARK). The tun2socks
// package installs `ip rule add fwmark <mark> lookup main` alongside the
// capture rules, so marked sockets keep using the host's original routing and
// everything else is captured. See internal/tun2socks/platform_linux.go.
//
// The mark is process-wide state rather than per-Engine because it describes
// the host's routing table, not any one engine's configuration: a process
// supervising TUN capture has exactly one of those. It is off unless capture
// actually started, so a run without capture behaves exactly as before.

// upstreamTimeout is the dial timeout the engine has always used for upstream
// connections; it is kept here so every site shares one value.
const upstreamTimeout = 10 * time.Second

// marking reports whether the engine should stamp its outbound sockets. It is
// process-wide because it describes the host's routing table, not any one
// engine's configuration, and a process supervising TUN capture has exactly one
// of those.
var marking atomic.Bool

// egressMark is the SO_MARK value the ip rule matches. Read by the socket
// Control hook on every dial, so it is an atomic rather than a plain int.
var egressMark atomic.Uint32

// markWarnOnce keeps a kernel that refuses SO_MARK (no CAP_NET_ADMIN) from
// logging on every single dial.
var markWarnOnce sync.Once

// SetUpstreamEgressMark marks every subsequent outbound socket with mark, so
// policy routing can exempt the engine's own traffic from TUN capture. Pass 0
// to stop marking. Only `webfilter run`/`proxy` on a host where TUN capture
// actually started calls this.
//
// Setting SO_MARK needs CAP_NET_ADMIN - but so does creating the TUN device
// and installing the routing rules, so any process that gets far enough to
// call this already holds it.
func SetUpstreamEgressMark(mark uint32) {
	egressMark.Store(mark)
	marking.Store(mark != 0)
}

// The two dialers are built once at init and never mutated, so a call to
// SetUpstreamEgressMark cannot race a concurrent dial. Which one a caller gets
// is decided per call by reading the atomic above.
//
// They differ in one more thing than the name suggests: the marked dialer
// resolves names through Go's own resolver. Hostname lookups are outbound
// traffic too, and the stock resolver opens its own sockets that never pass
// through Dialer.Control - so without PreferGo the engine's DNS would be
// captured and looped even though every other socket was exempt. That is a
// real behavioural change (nsswitch and mDNS stop applying), which is why it
// is scoped to hosts actually running capture rather than turned on globally.
var (
	plainDialer = &net.Dialer{Timeout: upstreamTimeout}

	markedDialer = &net.Dialer{
		Timeout: upstreamTimeout,
		Control: controlUpstreamSocket,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := &net.Dialer{Timeout: upstreamTimeout, Control: controlUpstreamSocket}
				return d.DialContext(ctx, network, address)
			},
		},
	}

	plainListenConfig  = &net.ListenConfig{}
	markedListenConfig = &net.ListenConfig{Control: controlUpstreamSocket}
)

// upstreamDialer returns the dialer matching the current capture state.
func upstreamDialer() *net.Dialer {
	if marking.Load() {
		return markedDialer
	}
	return plainDialer
}

func upstreamListenConfig() *net.ListenConfig {
	if marking.Load() {
		return markedListenConfig
	}
	return plainListenConfig
}

// DialUpstreamContext dials an upstream address with the engine's shared
// dialer.
func DialUpstreamContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return upstreamDialer().DialContext(ctx, network, addr)
}

// DialUpstream is DialUpstreamContext without a context, for the callers that
// have none.
func DialUpstream(network, addr string) (net.Conn, error) {
	return upstreamDialer().Dial(network, addr)
}

// DialUpstreamTimeout is net.DialTimeout with the engine's egress marking.
func DialUpstreamTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	d := *upstreamDialer()
	d.Timeout = timeout
	return d.Dial(network, addr)
}

// UpstreamDialer returns a copy of the shared dialer with the given timeout,
// for APIs that insist on owning a *net.Dialer (tls.DialWithDialer).
func UpstreamDialer(timeout time.Duration) *net.Dialer {
	d := *upstreamDialer()
	d.Timeout = timeout
	return &d
}

// ListenUpstreamPacket binds a UDP socket carrying the engine's egress mark.
func ListenUpstreamPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return upstreamListenConfig().ListenPacket(ctx, network, addr)
}

// warnMarkUnavailable reports a refused SO_MARK once. A failure here is not
// fatal: the socket still works, it is just not exempt from capture, which is
// worth knowing about but not worth failing every request over.
func warnMarkUnavailable(err error) {
	markWarnOnce.Do(func() {
		slog.Warn("could not mark upstream socket for TUN-capture bypass; "+
			"the engine's own traffic may be routed back into the tunnel",
			"err", err)
	})
}
