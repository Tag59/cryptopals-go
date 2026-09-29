package set1_test

import (
	"strings"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 8 — Detect AES in ECB mode.
// ECB is deterministic per block: same 16-byte plaintext block, same
// ciphertext block. Among 204 ciphertexts, the one encrypted with ECB is the
// only one containing repeated blocks — no key needed to spot it.
// Lesson: ECB leaks equality of blocks, hence structure (the "ECB penguin").
func TestChallenge08(t *testing.T) {
	lines := readLines(t, "testdata/8.txt")

	var detected []int
	for i, line := range lines {
		n, err := aesutil.RepeatedBlocks(mustHex(t, line), aesutil.BlockSize)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if n > 0 {
			detected = append(detected, i)
		}
	}

	if len(detected) != 1 {
		t.Fatalf("detected %d ECB candidates (%v), want exactly 1", len(detected), detected)
	}
	if i := detected[0]; i != 132 || !strings.HasPrefix(lines[i], "d880619740a8a19b") {
		t.Errorf("detected line %d, want line 132 starting with d880619740a8a19b", i)
	}
}
