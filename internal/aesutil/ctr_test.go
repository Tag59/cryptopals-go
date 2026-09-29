package aesutil

import (
	"bytes"
	"testing"
)

func TestCTRRoundTrip(t *testing.T) {
	key := RandomBytes(16)
	for _, n := range []int{0, 1, 15, 16, 17, 100} {
		pt := RandomBytes(n)
		ct, err := CTR(key, 42, pt)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != n {
			t.Fatalf("len %d: ciphertext length %d (CTR must not pad)", n, len(ct))
		}
		back, err := CTR(key, 42, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back, pt) {
			t.Errorf("len %d: round trip mismatch", n)
		}
	}
}

// The keystream for block i must be E_k(nonce_le || i_le), which ECB lets us
// compute independently.
func TestCTRKeystreamLayout(t *testing.T) {
	key := RandomBytes(16)
	ks, err := CTR(key, 7, make([]byte, 2*BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	counters := []byte{
		7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
	}
	want, err := ECBEncrypt(key, counters)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ks, want) {
		t.Errorf("keystream = %x, want %x", ks, want)
	}
}
