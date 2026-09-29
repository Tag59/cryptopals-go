package set1_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/freq"
)

// Challenge 3 — Single-byte XOR cipher.
// Only 256 possible keys: try them all and keep the plaintext that looks most
// like English (letter + space frequencies, heavy penalty for control bytes).
// Lesson: a keyspace you can enumerate is no keyspace at all.
func TestChallenge03(t *testing.T) {
	ct := mustHex(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	got, err := freq.BreakSingleByteXOR(ct)
	if err != nil {
		t.Fatalf("BreakSingleByteXOR: %v", err)
	}
	if got.Key != 'X' {
		t.Errorf("key = %q, want 'X'", got.Key)
	}
	assertSHA256(t, got.Plaintext, "c93fc1ebee779045574aaac6aad7e6f0ac9e2b545efdd4dd6ed03c8bcee163e1")
}
