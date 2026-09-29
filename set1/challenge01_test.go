package set1_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// Challenge 1 — Convert hex to base64.
// Warm-up: decode to raw bytes, re-encode. Establishes the "work on bytes" rule.
func TestChallenge01(t *testing.T) {
	const (
		in   = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		want = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	got, err := xorutil.HexToBase64(in)
	if err != nil {
		t.Fatalf("HexToBase64: %v", err)
	}
	if got != want {
		t.Errorf("HexToBase64 = %q, want %q", got, want)
	}
}
