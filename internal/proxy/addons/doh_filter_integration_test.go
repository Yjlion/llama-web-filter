package addons_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

// fakeDoh starts an httptest server implementing just enough of RFC 8484
// to drive DohFilter end-to-end: it parses the wireformat query and
// answers every A/AAAA question with rcode.
func fakeDoh(t *testing.T, rcode int) *httptest.Server {
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
		w.Write(wire)
	}))
}

func TestDohFilterBlocksOnNXDOMAIN(t *testing.T) {
	server := fakeDoh(t, dns.RcodeNameError)
	defer server.Close()

	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://blocked.example.com/")
	policy := models.NewPolicy()
	policy.Doh = models.DohConfig{Enabled: true, Server: server.URL}
	fc.Policy = &policy

	addons.DohFilter{}.HandleRequest(fc)

	if fc.Response == nil {
		t.Fatal("expected NXDOMAIN from the DoH resolver to block the request")
	}
}

func TestDohFilterAllowsOnSuccess(t *testing.T) {
	server := fakeDoh(t, dns.RcodeSuccess)
	defer server.Close()

	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://allowed.example.com/")
	policy := models.NewPolicy()
	policy.Doh = models.DohConfig{Enabled: true, Server: server.URL}
	fc.Policy = &policy

	addons.DohFilter{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Fatal("did not expect a successful resolution to be blocked")
	}
}

func TestDohFilterDisabledIsNoop(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	policy := models.NewPolicy()
	policy.Doh = models.DohConfig{Enabled: false}
	fc.Policy = &policy

	addons.DohFilter{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Fatal("did not expect any effect when doh is disabled")
	}
}

func TestDohFilterExcludeSkipsFiltering(t *testing.T) {
	server := fakeDoh(t, dns.RcodeNameError)
	defer server.Close()

	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://excluded.example.com/")
	policy := models.NewPolicy()
	policy.Doh = models.DohConfig{Enabled: true, Server: server.URL, Exclude: []string{"excluded.example.com"}}
	fc.Policy = &policy

	addons.DohFilter{}.HandleRequest(fc)

	if fc.Response != nil {
		t.Fatal("expected excluded domain to skip DOH filtering entirely")
	}
}
