package set2_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 9 — Implement PKCS#7 padding.
// Pad with n bytes of value n. A full block is added when the input is already
// aligned, so the last byte always tells how much to strip. The implementation
// lives in internal/aesutil/pkcs7.go (written for challenge 7).
func TestChallenge09(t *testing.T) {
	got, err := aesutil.PKCS7Pad([]byte("YELLOW SUBMARINE"), 20)
	if err != nil {
		t.Fatalf("PKCS7Pad: %v", err)
	}
	if want := "YELLOW SUBMARINE\x04\x04\x04\x04"; string(got) != want {
		t.Errorf("PKCS7Pad = %q, want %q", got, want)
	}
}
