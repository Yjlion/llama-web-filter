package proxy

import (
	"net"
	"strconv"
	"testing"

	"github.com/miekg/dns"
)

// startFakeUDPDNS runs a plain UDP DNS server on loopback answering every query
// via reply, returning its address. Stands in for the resolver the mobile
// VpnService points the client at.
func startFakeUDPDNS(t *testing.T, reply func(*dns.Msg) *dns.Msg) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fake dns: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			_ = w.WriteMsg(reply(r))
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestResolveDNSPlainForward covers the DoH-disabled path: resolveDNS must
// forward the query verbatim to the addressed resolver and relay its answer
// back with the transaction id preserved. (The port-53 gating and the full
// relay round-trip are covered end-to-end by the external-package tests; this
// exercises the plain-forward branch without needing to bind port 53.)
func TestResolveDNSPlainForward(t *testing.T) {
	dnsAddr := startFakeUDPDNS(t, func(r *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 2, 3, 4),
		})
		return resp
	})
	host, portStr, _ := net.SplitHostPort(dnsAddr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	wire, _ := q.Pack()

	// No Runtime → GetPolicy is skipped, policy is nil, plain-forward branch.
	eng := &Engine{}
	respWire := eng.resolveDNS(wire, host, port, "127.0.0.1")
	if respWire == nil {
		t.Fatal("resolveDNS returned nil (plain forward failed)")
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if resp.Id != q.Id {
		t.Errorf("response id = %d, want %d (transaction id must be preserved)", resp.Id, q.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Errorf("answer = %v, want A 1.2.3.4", resp.Answer[0])
	}
}

// TestDecodeSocksUDPPacket checks the request parser against a hand-built
// IPv4 SOCKS UDP datagram and rejects a fragmented one.
func TestDecodeSocksUDPPacket(t *testing.T) {
	// RSV RSV FRAG ATYP=IPv4 1.1.1.1 :53 "payload"
	pkt := []byte{0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35}
	pkt = append(pkt, []byte("payload")...)

	raw, host, port, payload, err := decodeSocksUDPPacket(pkt)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if host != "1.1.1.1" || port != 53 {
		t.Errorf("host:port = %s:%d, want 1.1.1.1:53", host, port)
	}
	if string(payload) != "payload" {
		t.Errorf("payload = %q, want payload", payload)
	}
	if len(raw) != 1+net.IPv4len+2 {
		t.Errorf("raw addr len = %d, want 7", len(raw))
	}

	frag := append([]byte(nil), pkt...)
	frag[2] = 0x01 // fragmented
	if _, _, _, _, err := decodeSocksUDPPacket(frag); err == nil {
		t.Error("expected fragmented packet to be rejected")
	}
}

// dnsQueryWire builds a realistic stub-resolver query wire for the sniff tests.
func dnsQueryWire(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return wire
}

// dnsResponseWire builds a DNS *response* wire - which must never be treated
// as a query to re-resolve.
func dnsResponseWire(t *testing.T, name string) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(1, 2, 3, 4),
	})
	wire, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return wire
}

// TestUDPVerdictFor pins the relay's datagram policy. The drop cases are what
// matter for filtering integrity: QUIC (443) and DoQ (853) are end-to-end
// encrypted with no MITM seam, so relaying them would let a client behind the
// TUN bypass the addon pipeline and the DNS filter respectively. DNS is routed
// through the policy-aware resolver on any port, because "the resolver lives on
// 53" is a convention a client can simply ignore. Everything else forwards,
// because the engine cannot inspect opaque UDP and dropping it only breaks the
// OS.
//
// This is asserted here rather than end-to-end because a dropped datagram and
// one forwarded to a closed port are indistinguishable from the client side.
func TestUDPVerdictFor(t *testing.T) {
	query := dnsQueryWire(t, "example.com")
	response := dnsResponseWire(t, "example.com")
	// A plausible non-DNS datagram: a WireGuard handshake initiation begins
	// with type 1 and three reserved zero bytes.
	wireguard := append([]byte{0x01, 0x00, 0x00, 0x00}, make([]byte, 144)...)

	for _, tc := range []struct {
		name    string
		port    int
		payload []byte
		want    udpVerdict
	}{
		{"quic is dropped", quicPort, nil, udpDrop},
		{"dns-over-quic is dropped", dotPort, query, udpDrop},
		{"dns is resolved through policy", dnsPort, query, udpResolveDNS},
		{"ntp forwards", 123, nil, udpForward},
		{"wireguard forwards", 51820, wireguard, udpForward},
		{"https over tcp's port number, but udp, is still quic", 443, nil, udpDrop},
		{"quic on a nonstandard port is not special-cased", 8443, nil, udpForward},
		{"a resolver on a nonstandard port is still filtered", 5353, query, udpResolveDNS},
		{"a dns response is not a query to re-resolve", 5353, response, udpForward},
		{"an empty payload forwards", 5353, nil, udpForward},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := udpVerdictFor(tc.port, tc.payload); got != tc.want {
				t.Errorf("udpVerdictFor(%d, %d bytes) = %v, want %v", tc.port, len(tc.payload), got, tc.want)
			}
		})
	}
}

// TestLooksLikeDNSQuery guards the sniff's strictness directly: rerouting an
// unrelated protocol through resolveDNS would be a silent behaviour change for
// every UDP flow on a TUN-captured machine.
func TestLooksLikeDNSQuery(t *testing.T) {
	query := dnsQueryWire(t, "example.com")

	if !looksLikeDNSQuery(query) {
		t.Error("a real stub-resolver query should be recognized")
	}
	if looksLikeDNSQuery(dnsResponseWire(t, "example.com")) {
		t.Error("a response is not a query")
	}
	if looksLikeDNSQuery(query[:8]) {
		t.Error("a truncated header is not a query")
	}
	if looksLikeDNSQuery(make([]byte, maxSniffedDNSQuery+1)) {
		t.Error("an oversized datagram should not be sniffed")
	}

	truncated := append([]byte(nil), query...)
	truncated[2] |= 0x02 // TC
	if looksLikeDNSQuery(truncated) {
		t.Error("a truncated-flag query should be rejected")
	}

	notify := append([]byte(nil), query...)
	notify[2] = (notify[2] & 0x87) | (4 << 3) // opcode NOTIFY
	if looksLikeDNSQuery(notify) {
		t.Error("only opcode QUERY should be recognized")
	}

	twoQuestions := append([]byte(nil), query...)
	twoQuestions[5] = 2
	if looksLikeDNSQuery(twoQuestions) {
		t.Error("a multi-question datagram should be rejected")
	}
}
