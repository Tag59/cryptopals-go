package set2_test

import (
	"errors"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 15 — PKCS#7 padding validation.
// Unpadding must check every padding byte, not just trust the last one.
// aesutil.PKCS7Unpad already does (it was written strict for challenge 7).
// Keep in mind that this very check, once its outcome is observable remotely,
// becomes the padding oracle of challenge 17.
func TestChallenge15(t *testing.T) {
	valid, err := aesutil.PKCS7Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"), aesutil.BlockSize)
	if err != nil {
		t.Fatalf("valid padding rejected: %v", err)
	}
	if string(valid) != "ICE ICE BABY" {
		t.Errorf("PKCS7Unpad = %q, want %q", valid, "ICE ICE BABY")
	}

	for _, in := range []string{
		"ICE ICE BABY\x05\x05\x05\x05",
		"ICE ICE BABY\x01\x02\x03\x04",
	} {
		if _, err := aesutil.PKCS7Unpad([]byte(in), aesutil.BlockSize); !errors.Is(err, aesutil.ErrInvalidPadding) {
			t.Errorf("PKCS7Unpad(%q): got err %v, want ErrInvalidPadding", in, err)
		}
	}
}
