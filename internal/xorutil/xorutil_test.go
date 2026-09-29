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

func TestRepeatingKeyRoundTrip(t *testing.T) {
	pt, key := []byte("round trip"), []byte("key")
	ct, err := RepeatingKey(pt, key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := RepeatingKey(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(pt) {
		t.Errorf("round trip = %q, want %q", back, pt)
	}
}

func TestRepeatingKeyEmptyKey(t *testing.T) {
	if _, err := RepeatingKey([]byte("x"), nil); !errors.Is(err, ErrEmptyKey) {
		t.Errorf("got err %v, want ErrEmptyKey", err)
	}
}
