package pwhash_test

import (
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := pwhash.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "pbkdf2_sha256$200000$") {
		t.Errorf("hash format = %q, want pbkdf2_sha256$200000$... prefix", h)
	}
	if !pwhash.Verify("correct horse battery staple", h) {
		t.Errorf("Verify should succeed for the correct password")
	}
	if pwhash.Verify("wrong password", h) {
		t.Errorf("Verify should fail for the wrong password")
	}
}

func TestVerifyMalformedNeverPanics(t *testing.T) {
	cases := []string{"", "not-a-hash", "pbkdf2_sha256$abc$def", "pbkdf2_sha256$200000$zz$zz", "md5$1$a$b"}
	for _, c := range cases {
		if pwhash.Verify("anything", c) {
			t.Errorf("Verify(%q) = true, want false", c)
		}
	}
}
