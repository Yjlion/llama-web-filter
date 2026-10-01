package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

// clientHelloFor produces a real ClientHello for name by letting crypto/tls
// write one into a pipe. Hand-rolling the bytes would only test the parser
// against my own idea of the format; this tests it against the format Go
// actually emits, which is what arrives on the wire.
func clientHelloFor(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	conn := &captureConn{w: &buf}
	// The handshake fails (nothing answers), but not before the ClientHello is
	// written, which is all we need. An empty ServerName is the IP-literal
	// case and needs InsecureSkipVerify, or crypto/tls refuses before it
	// writes anything.
	cfg := &tls.Config{ServerName: name, InsecureSkipVerify: name == ""}
	_ = tls.Client(conn, cfg).Handshake()
	if buf.Len() == 0 {
		t.Fatal("crypto/tls wrote no ClientHello")
	}
	return buf.Bytes()
}

// captureConn records what is written and reports EOF on read.
type captureConn struct {
	net.Conn
	w *bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *captureConn) Read([]byte) (int, error)    { return 0, net.ErrClosed }
func (c *captureConn) Close() error                { return nil }

func peekOf(t *testing.T, b []byte) string {
	t.Helper()
	return peekRequestedHost(bufio.NewReaderSize(bytes.NewReader(b), 8192))
}

// Transparent capture recovers an address, but every host-scoped rule in the
// engine keys on a name. Without the SNI, a gateway would silently stop
// honouring hostname-based MITM exclusions, because every target would be an IP.
func TestPeekRequestedHostReadsSNI(t *testing.T) {
	for _, name := range []string{"example.com", "sub.domain.example.co.uk"} {
		if got := peekOf(t, clientHelloFor(t, name)); got != name {
			t.Errorf("peekRequestedHost() = %q, want %q", got, name)
		}
	}
}

// A TLS client never sends SNI for an IP literal (RFC 6066), so the peek must
// report nothing and leave the caller on the recovered address.
func TestPeekRequestedHostNoSNIForIPLiteral(t *testing.T) {
	if got := peekOf(t, clientHelloFor(t, "")); got != "" {
		t.Errorf("peekRequestedHost() = %q, want empty for an SNI-less hello", got)
	}
}

func TestPeekRequestedHostReadsHTTPHost(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nUser-Agent: curl/8\r\nHost: example.org\r\nAccept: */*\r\n\r\n"
	if got := peekOf(t, []byte(req)); got != "example.org" {
		t.Errorf("peekRequestedHost() = %q, want example.org", got)
	}
	withPort := "GET / HTTP/1.1\r\nHost: example.org:8080\r\n\r\n"
	if got := peekOf(t, []byte(withPort)); got != "example.org" {
		t.Errorf("peekRequestedHost() = %q, want the port stripped", got)
	}
}

// Peeking must never consume: handleTunnel re-reads the same bytes to decide
// how to intercept, and losing them would break every transparent connection.
func TestPeekRequestedHostDoesNotConsume(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
	r := bufio.NewReaderSize(bytes.NewReader(raw), 8192)
	if got := peekRequestedHost(r); got != "example.org" {
		t.Fatalf("peekRequestedHost() = %q", got)
	}
	rest, err := r.Peek(len(raw))
	if err != nil || !bytes.Equal(rest, raw) {
		t.Errorf("the peek consumed bytes: got %q (err %v)", rest, err)
	}
}

// Garbage must yield "" rather than a wrong name: misreporting the host would
// misroute policy, and falling back to the recovered IP is the safe answer.
func TestPeekRequestedHostRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"\x16",                      // a truncated TLS record
		"\x16\x03\x01\x00\x05zzzzz", // TLS record, not a ClientHello
		"\x16\x03\x01\xff\xffshort", // length longer than the data
		"NOTHTTP\r\n\r\n",           // no Host header
		strings.Repeat("A", 100),    // plain noise
	} {
		if got := peekOf(t, []byte(in)); got != "" {
			t.Errorf("peekRequestedHost(%q) = %q, want empty", in, got)
		}
	}
}

// A short first write must not stall: Peek(n) blocks until n bytes arrive, and
// the client is waiting on us before it sends any more.
func TestPeekRequestedHostDoesNotBlockOnShortWrites(t *testing.T) {
	hello := clientHelloFor(t, "example.com")
	r := bufio.NewReaderSize(newBlockAfter(hello), 8192)
	if got := peekRequestedHost(r); got != "example.com" {
		t.Errorf("peekRequestedHost() = %q, want example.com without waiting for more", got)
	}
}

// blockAfter yields its payload once and then blocks forever, standing in for a
// client that has sent its ClientHello and is waiting for a reply.
type blockAfter struct {
	data []byte
	done bool
	gate chan struct{}
}

func newBlockAfter(b []byte) *blockAfter {
	return &blockAfter{data: b, gate: make(chan struct{})}
}

func (b *blockAfter) Read(p []byte) (int, error) {
	if !b.done {
		b.done = true
		return copy(p, b.data), nil
	}
	<-b.gate // never returns; the test fails by timing out if we get here
	return 0, net.ErrClosed
}
