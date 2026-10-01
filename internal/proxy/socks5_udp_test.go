package proxy_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// startFakeDoh runs an httptest server implementing just enough of RFC 8484 to
// drive the UDP relay's DoH path: it parses the wireformat query and answers
// every question with rcode, preserving the transaction id.
func startFakeDoh(t *testing.T, rcode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = rcode
		wire, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
}

// socksUDPQuery drives a full SOCKS5 UDP ASSOCIATE against socksAddr and sends
// one DNS query wire destined for dstAddr (host:port), returning the DNS
// response wire the relay sends back. It keeps the TCP control connection open
// for the duration, as a real client must.
func socksUDPQuery(t *testing.T, socksAddr, dstAddr string, query []byte) []byte {
	t.Helper()

	relayAddr, ctrl := socksUDPAssociate(t, socksAddr)
	defer ctrl.Close()

	// Send the query wrapped in a SOCKS UDP header addressed to dstAddr.
	uc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(socksUDPTestDeadline))

	packet := encodeUDPRequest(t, dstAddr, query)
	if _, err := uc.Write(packet); err != nil {
		t.Fatalf("write relay packet: %v", err)
	}

	buf := make([]byte, 64*1024)
	n, err := uc.Read(buf)
	if err != nil {
		return nil
	}
	// Strip RSV(2) FRAG(1) ATYP+ADDR+PORT to get the DNS response payload.
	_, payload := decodeUDPReply(t, buf[:n])
	return payload
}

// socksUDPAssociate performs the SOCKS5 greeting and UDP ASSOCIATE handshake,
// returning the relay address the client should send datagrams to along with
// the TCP control connection. The association lives only as long as that
// connection, so the caller owns and must close it.
func socksUDPAssociate(t *testing.T, socksAddr string) (*net.UDPAddr, net.Conn) {
	t.Helper()

	ctrl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	t.Cleanup(func() { ctrl.Close() })
	_ = ctrl.SetDeadline(time.Now().Add(socksUDPTestDeadline))

	// Greeting + no-auth method selection.
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		t.Fatalf("method selection = %v, want [5 0]", sel)
	}

	// UDP ASSOCIATE request: DST.ADDR/PORT are 0.0.0.0:0 (client doesn't know).
	req := []byte{0x05, cmdUDPAssociateByte, 0x00, 0x01, 0, 0, 0, 0}
	req = binary.BigEndian.AppendUint16(req, 0)
	if _, err := ctrl.Write(req); err != nil {
		t.Fatalf("write associate: %v", err)
	}

	// Reply: VER, REP, RSV, then BND.ADDR (relay to send datagrams to).
	head := make([]byte, 3)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		t.Fatalf("read associate reply head: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("associate reply code = 0x%02x, want 0x00", head[1])
	}
	return readReplyAddr(t, ctrl), ctrl
}

// cmdUDPAssociateByte mirrors the unexported proxy.cmdUDPAssociate (0x03).
const cmdUDPAssociateByte = 0x03

// quicPort mirrors the unexported proxy.quicPort: the one UDP destination the
// relay refuses.
const quicPort = 443

// socksUDPTestDeadline bounds each relay round-trip in tests; the drop test
// relies on it to conclude no reply is coming for non-DNS UDP.
const socksUDPTestDeadline = 2 * time.Second

func readReplyAddr(t *testing.T, r io.Reader) *net.UDPAddr {
	t.Helper()
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		t.Fatalf("read reply atyp: %v", err)
	}
	var ipLen int
	switch atyp[0] {
	case 0x01:
		ipLen = net.IPv4len
	case 0x04:
		ipLen = net.IPv6len
	default:
		t.Fatalf("unexpected reply atyp 0x%02x", atyp[0])
	}
	rest := make([]byte, ipLen+2)
	if _, err := io.ReadFull(r, rest); err != nil {
		t.Fatalf("read reply addr: %v", err)
	}
	ip := net.IP(rest[:ipLen])
	port := int(binary.BigEndian.Uint16(rest[ipLen:]))
	return &net.UDPAddr{IP: ip, Port: port}
}

func encodeUDPRequest(t *testing.T, dstAddr string, payload []byte) []byte {
	t.Helper()
	host, portStr, err := net.SplitHostPort(dstAddr)
	if err != nil {
		t.Fatalf("split dst %q: %v", dstAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("dst host %q is not an IPv4 literal", host)
	}
	pkt := []byte{0x00, 0x00, 0x00, 0x01}
	pkt = append(pkt, ip...)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(port))
	pkt = append(pkt, payload...)
	return pkt
}

func decodeUDPReply(t *testing.T, pkt []byte) (dst string, payload []byte) {
	t.Helper()
	if len(pkt) < 4 {
		t.Fatalf("reply too short: %d bytes", len(pkt))
	}
	if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		t.Fatalf("reply RSV/FRAG not zero: %v", pkt[:3])
	}
	var addrLen int
	switch pkt[3] {
	case 0x01:
		addrLen = 1 + net.IPv4len + 2
	case 0x04:
		addrLen = 1 + net.IPv6len + 2
	default:
		t.Fatalf("reply atyp 0x%02x unsupported in test", pkt[3])
	}
	return "", pkt[3+addrLen:]
}

// TestSocks5UDPFiltersViaDoh verifies that when the applicable policy enables
// DoH, queries route through the policy's DoH server (a filtering resolver) and
// a blocked name comes back NXDOMAIN and is logged as a block.
func TestSocks5UDPFiltersViaDoh(t *testing.T) {
	doh := startFakeDoh(t, dns.RcodeNameError)
	defer doh.Close()

	socksAddr, rt := startSocksEngine(t, nil, nil, nil)
	seedDohPolicy(t, rt, doh.URL)

	q := new(dns.Msg)
	q.SetQuestion("blocked.example.com.", dns.TypeA)
	wire, _ := q.Pack()

	// dstAddr is ignored on the DoH path (we forward to the policy server), but
	// must still be port 53 to be treated as DNS.
	respWire := socksUDPQuery(t, socksAddr, "1.1.1.1:53", wire)
	if respWire == nil {
		t.Fatal("no DNS response relayed")
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN (blocked)", dns.RcodeToString[resp.Rcode])
	}

	blocks := rt.Logs.Tail("blocks", 10)
	found := false
	for _, b := range blocks {
		if b["domain"] == "blocked.example.com" && b["component"] == "doh" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a doh block log for blocked.example.com, got %v", blocks)
	}
}

// TestSocks5UDPDropsQUIC checks end-to-end that UDP/443 gets no reply. Binding
// port 443 needs root, so this cannot distinguish "the relay dropped it" from
// "it was forwarded to a closed port" - TestUDPVerdictFor pins the rule itself.
// What this adds is that nothing downstream of the verdict (the reply path, the
// session map) accidentally answers a QUIC datagram anyway.
func TestSocks5UDPDropsQUIC(t *testing.T) {
	socksAddr, _ := startSocksEngine(t, nil, nil, nil)
	quicAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(quicPort))

	// socksUDPQuery bounds the client read; a dropped datagram yields no reply.
	if resp := socksUDPQuery(t, socksAddr, quicAddr, []byte("quic-ish")); resp != nil {
		t.Errorf("UDP/%d got a relayed reply (%d bytes); want it dropped", quicPort, len(resp))
	}
}

// TestSocks5UDPRelaysGenericUDP verifies that UDP other than DNS and QUIC is
// forwarded verbatim. The engine cannot inspect opaque UDP anyway, so dropping
// it bought no filtering coverage while breaking NTP, VoIP, games and anything
// else the OS sends once a TUN is capturing all traffic.
func TestSocks5UDPRelaysGenericUDP(t *testing.T) {
	socksAddr, _ := startSocksEngine(t, nil, nil, nil)
	echo := startUDPEcho(t)

	payload := []byte("hello over plain udp")
	resp := socksUDPQuery(t, socksAddr, echo.String(), payload)
	if resp == nil {
		t.Fatal("no reply relayed for generic UDP; want it forwarded")
	}
	if !bytes.Equal(resp, payload) {
		t.Errorf("relayed reply = %q, want the echoed payload %q", resp, payload)
	}
}

// TestSocks5UDPIgnoresForeignSource verifies the relay only accepts datagrams
// from the client that opened the association. The relay port is otherwise an
// open forwarder for any local process that guesses it.
func TestSocks5UDPIgnoresForeignSource(t *testing.T) {
	socksAddr, _ := startSocksEngine(t, nil, nil, nil)
	echo := startUDPEcho(t)

	relayAddr, ctrl := socksUDPAssociate(t, socksAddr)
	defer ctrl.Close()

	// First datagram pins the association to this socket's address.
	pinned, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer pinned.Close()
	_ = pinned.SetDeadline(time.Now().Add(socksUDPTestDeadline))
	if _, err := pinned.Write(encodeUDPRequest(t, echo.String(), []byte("first"))); err != nil {
		t.Fatalf("write pinning datagram: %v", err)
	}
	buf := make([]byte, 64*1024)
	if _, err := pinned.Read(buf); err != nil {
		t.Fatalf("pinning datagram got no reply: %v", err)
	}

	// A second local socket is a different source port, so it must be ignored.
	foreign, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay from a second socket: %v", err)
	}
	defer foreign.Close()
	_ = foreign.SetDeadline(time.Now().Add(socksUDPTestDeadline))
	if _, err := foreign.Write(encodeUDPRequest(t, echo.String(), []byte("intruder"))); err != nil {
		t.Fatalf("write foreign datagram: %v", err)
	}
	if n, err := foreign.Read(buf); err == nil {
		t.Errorf("relay answered a foreign source address with %d bytes; want it ignored", n)
	}
}

// startUDPEcho runs a UDP echo server for the test's lifetime and returns its
// address.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// seedDohPolicy writes a catch-all policy with DoH enabled into the runtime's
// policies dir and reloads, so GetPolicy(127.0.0.1) returns it.
func seedDohPolicy(t *testing.T, rt *state.Runtime, dohServer string) {
	t.Helper()
	dir := rt.Settings().PoliciesDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	body := `{"name":"default","doh":{"enabled":true,"server":"` + dohServer + `"}}`
	if err := os.WriteFile(filepath.Join(dir, "default.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	rt.ReloadPolicies()
}
