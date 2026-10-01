package addons

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestClassifyDohNXDOMAIN(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError

	blocked, detail, _ := classifyDoh([]*dns.Msg{msg})
	if !blocked || detail != "NXDOMAIN" {
		t.Errorf("classifyDoh = (%v, %q), want (true, NXDOMAIN)", blocked, detail)
	}
}

func TestClassifyDohEDEBlocked(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: 15, ExtraText: "Blocked by policy"})
	msg.Extra = append(msg.Extra, opt)

	blocked, detail, _ := classifyDoh([]*dns.Msg{msg})
	if !blocked {
		t.Fatal("expected EDE 15 to classify as blocked")
	}
	if detail != "EDE 15: Blocked by policy" {
		t.Errorf("detail = %q", detail)
	}
}

func TestClassifyDohEDENonBlockingCodeIgnored(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: 1, ExtraText: "Unsupported DNSKEY algorithm"})
	msg.Extra = append(msg.Extra, opt)

	blocked, _, _ := classifyDoh([]*dns.Msg{msg})
	if blocked {
		t.Error("expected a non-blocking EDE info-code to not classify as blocked")
	}
}

func TestClassifyDohSinkholeIP(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "blocked.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("0.0.0.0"),
	}
	msg.Answer = append(msg.Answer, rr)

	blocked, detail, ttl := classifyDoh([]*dns.Msg{msg})
	if !blocked || detail != "block-ip 0.0.0.0" {
		t.Errorf("classifyDoh = (%v, %q), want (true, block-ip 0.0.0.0)", blocked, detail)
	}
	if ttl != 60*time.Second {
		t.Errorf("ttl = %v, want 60s", ttl)
	}
}

func TestClassifyDohAllowedResolvesNormally(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   net.ParseIP("93.184.216.34"),
	}
	msg.Answer = append(msg.Answer, rr)

	blocked, _, ttl := classifyDoh([]*dns.Msg{msg})
	if blocked {
		t.Error("did not expect a normal resolution to classify as blocked")
	}
	if ttl != 120*time.Second {
		t.Errorf("ttl = %v, want 120s", ttl)
	}
}
