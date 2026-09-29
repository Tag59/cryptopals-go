package xorutil

import "testing"

func TestHexToBase64InvalidHex(t *testing.T) {
	for _, in := range []string{"abc", "zz"} {
		if _, err := HexToBase64(in); err == nil {
			t.Errorf("HexToBase64(%q): expected error", in)
		}
	}
}
