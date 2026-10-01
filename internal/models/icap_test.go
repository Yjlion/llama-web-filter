package models_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// A settings.json written before ICAP existed must still produce a usable
// ICAP config, because the block is created by the defaults rather than by
// the file.
func TestIcapConfigDefaultsWhenAbsent(t *testing.T) {
	var s models.GlobalSettings
	if err := json.Unmarshal([]byte(`{"mgmt_port": 8000}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Icap.PreviewSize != 4096 {
		t.Errorf("PreviewSize = %d, want 4096", s.Icap.PreviewSize)
	}
	if s.Icap.MaxBodyBytes != 8<<20 {
		t.Errorf("MaxBodyBytes = %d, want %d", s.Icap.MaxBodyBytes, 8<<20)
	}
	if !s.Icap.NormalizeAcceptEncoding {
		t.Error("NormalizeAcceptEncoding = false, want true")
	}
	if !s.Icap.TrustClientIPHeader {
		t.Error("TrustClientIPHeader = false, want true")
	}
}

// Every sub-config resets to its defaults before overlaying the input, so a
// partial block must keep the fields it did not mention - the failure mode
// this guards is a one-key edit silently zeroing the rest.
func TestIcapConfigPartialBlockKeepsDefaults(t *testing.T) {
	var s models.GlobalSettings
	if err := json.Unmarshal([]byte(`{"icap": {"preview_size": 1024}}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Icap.PreviewSize != 1024 {
		t.Errorf("PreviewSize = %d, want 1024", s.Icap.PreviewSize)
	}
	if s.Icap.MaxBodyBytes != 8<<20 {
		t.Errorf("MaxBodyBytes = %d, want the default to survive", s.Icap.MaxBodyBytes)
	}
	if !s.Icap.TrustClientIPHeader {
		t.Error("TrustClientIPHeader was reset by an unrelated edit")
	}
}

// A zero or negative body cap is not "unlimited", it is a footgun: it would
// either buffer nothing (filtering everything open) or everything.
func TestIcapConfigRejectsNonPositiveBodyCap(t *testing.T) {
	var s models.GlobalSettings
	if err := json.Unmarshal([]byte(`{"icap": {"max_body_bytes": 0, "preview_size": -5}}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Icap.MaxBodyBytes != 8<<20 {
		t.Errorf("MaxBodyBytes = %d, want the default for a non-positive value", s.Icap.MaxBodyBytes)
	}
	if s.Icap.PreviewSize != 0 {
		t.Errorf("PreviewSize = %d, want a negative preview clamped to 0", s.Icap.PreviewSize)
	}
}

func TestIcapConfigRoundTrips(t *testing.T) {
	in := models.NewIcapConfig()
	in.PreviewSize = 2048
	in.NormalizeAcceptEncoding = false

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out models.IcapConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\n  in:  %+v\n  out: %+v", in, out)
	}
}
