package macutil_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/macutil"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":      "aa:bb:cc:dd:ee:ff",
		"invalid":           "",
		"aa:bb:cc:dd:ee":    "",
		"":                  "",
		"gg:bb:cc:dd:ee:ff": "",
	}
	for in, want := range cases {
		if got := macutil.Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
