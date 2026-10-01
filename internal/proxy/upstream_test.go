package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The egress mark is process-wide state, so a run without TUN capture must
// leave it at zero - otherwise every deployment would be stamping a firewall
// mark nothing matches.
func TestUpstreamEgressMarkDefaultsOff(t *testing.T) {
	if marking.Load() {
		t.Fatal("marking is on at rest; a run without TUN capture must not mark sockets")
	}
	if got := egressMark.Load(); got != 0 {
		t.Fatalf("egressMark = %#x at rest, want 0", got)
	}
	// The unmarked dialer must also keep the stock resolver: PreferGo changes
	// how names are resolved, and that is only justified where capture runs.
	if upstreamDialer().Resolver != nil {
		t.Error("the default dialer has a custom resolver with no capture configured")
	}
}

func TestSetUpstreamEgressMarkRoundTrips(t *testing.T) {
	t.Cleanup(func() { SetUpstreamEgressMark(0) })

	SetUpstreamEgressMark(0x5745)
	if got := egressMark.Load(); got != 0x5745 {
		t.Errorf("egressMark = %#x, want 0x5745", got)
	}
	if !marking.Load() {
		t.Error("SetUpstreamEgressMark(0x5745) did not turn marking on")
	}
	// Name resolution is outbound traffic too: without a marked resolver the
	// engine's own DNS lookups are captured and loop back into it.
	if upstreamDialer().Resolver == nil {
		t.Error("the marked dialer resolves names through unmarked sockets")
	}
	if upstreamDialer().Control == nil {
		t.Error("the marked dialer has no Control hook, so nothing sets SO_MARK")
	}

	SetUpstreamEgressMark(0)
	if marking.Load() {
		t.Error("SetUpstreamEgressMark(0) did not turn marking off")
	}
	if upstreamDialer().Resolver != nil {
		t.Error("clearing the mark left the PreferGo resolver in place")
	}
}

// Whatever the mark does or doesn't do at the socket level, the dialers must
// still dial. This is the guard against a Control func that returns an error
// and silently breaks every upstream fetch on a host without CAP_NET_ADMIN.
func TestUpstreamDialersStillConnectWhileMarked(t *testing.T) {
	t.Cleanup(func() { SetUpstreamEgressMark(0) })
	SetUpstreamEgressMark(0x5745)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	for _, tc := range []struct {
		name string
		dial func() (net.Conn, error)
	}{
		{"DialUpstream", func() (net.Conn, error) { return DialUpstream("tcp", addr) }},
		{"DialUpstreamTimeout", func() (net.Conn, error) {
			return DialUpstreamTimeout("tcp", addr, 5*time.Second)
		}},
		{"DialUpstreamContext", func() (net.Conn, error) {
			return DialUpstreamContext(context.Background(), "tcp", addr)
		}},
		{"UpstreamDialer", func() (net.Conn, error) {
			return UpstreamDialer(5*time.Second).Dial("tcp", addr)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tc.dial()
			if err != nil {
				t.Fatalf("%s = %v, want a working connection", tc.name, err)
			}
			conn.Close()
		})
	}

	pc, err := ListenUpstreamPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUpstreamPacket() = %v", err)
	}
	pc.Close()
}

// NewTransport is what fetches every upstream response, so its dialer has to
// be the shared one or the mark never reaches the traffic that matters most.
func TestNewTransportUsesTheSharedDialer(t *testing.T) {
	if NewTransport().DialContext == nil {
		t.Fatal("NewTransport().DialContext is nil; upstream fetches bypass the egress mark")
	}
}
