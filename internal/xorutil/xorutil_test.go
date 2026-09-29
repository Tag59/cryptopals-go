package xorutil

import (
	"errors"
	"testing"
)

func TestHexToBase64InvalidHex(t *testing.T) {
	for _, in := range []string{"abc", "zz"} {
		if _, err := HexToBase64(in); err == nil {
			t.Errorf("HexToBase64(%q): expected error", in)
		}
	}
}

func TestFixedLengthMismatch(t *testing.T) {
	if _, err := Fixed([]byte{1, 2}, []byte{1}); !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("Fixed: got err %v, want ErrLengthMismatch", err)
	}
}
