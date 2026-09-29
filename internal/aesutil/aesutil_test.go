package aesutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// FIPS-197 Appendix C.1 known-answer test for AES-128.
func TestECBKnownAnswer(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	pt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	const want = "69c4e0d86a7b0430d8cdb78070b4c55a"

	ct, err := ECBEncrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ct) != want {
		t.Errorf("ECBEncrypt = %x, want %s", ct, want)
	}
	back, err := ECBDecrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, pt) {
		t.Errorf("ECBDecrypt = %x, want %x", back, pt)
	}
}

func TestECBErrors(t *testing.T) {
	if _, err := ECBEncrypt(make([]byte, 16), make([]byte, 15)); !errors.Is(err, ErrNotBlockAligned) {
		t.Errorf("unaligned input: got err %v, want ErrNotBlockAligned", err)
	}
	if _, err := ECBEncrypt(make([]byte, 7), make([]byte, 16)); err == nil {
		t.Error("bad key size: expected error")
	}
}

func TestPKCS7RoundTrip(t *testing.T) {
	for n := range 40 {
		in := bytes.Repeat([]byte{'A'}, n)
		padded, err := PKCS7Pad(in, BlockSize)
		if err != nil {
			t.Fatal(err)
		}
		if len(padded)%BlockSize != 0 || len(padded) <= n {
			t.Fatalf("len %d: padded length %d", n, len(padded))
		}
		out, err := PKCS7Unpad(padded, BlockSize)
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if !bytes.Equal(out, in) {
			t.Errorf("len %d: round trip mismatch", n)
		}
	}
}

func TestPKCS7UnpadRejects(t *testing.T) {
	bad := map[string][]byte{
		"empty":        {},
		"unaligned":    []byte("ICE ICE BABY\x04\x04\x04"),
		"zero byte":    []byte("ICE ICE BABY\x00\x00\x00\x00"),
		"inconsistent": []byte("ICE ICE BABY\x01\x02\x03\x04"),
		"too large":    []byte("ICE ICE BABY\x05\x05\x05\x11"),
	}
	for name, in := range bad {
		if _, err := PKCS7Unpad(in, BlockSize); !errors.Is(err, ErrInvalidPadding) {
			t.Errorf("%s: got err %v, want ErrInvalidPadding", name, err)
		}
	}
}
