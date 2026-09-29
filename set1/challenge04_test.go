package set1_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/freq"
)

// Challenge 4 — Detect single-character XOR.
// Same attack as challenge 3, run on every line: the line that was really
// encrypted yields a plaintext scoring far above the random-looking ones.
// The score doubles as a distinguisher — we detect *and* decrypt in one pass.
func TestChallenge04(t *testing.T) {
	lines := readLines(t, "testdata/4.txt")

	var (
		best    freq.SingleByteResult
		bestIdx = -1
	)
	for i, line := range lines {
		r, err := freq.BreakSingleByteXOR(mustHex(t, line))
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if bestIdx < 0 || r.Score > best.Score {
			best, bestIdx = r, i
		}
	}

	if bestIdx != 170 || best.Key != '5' {
		t.Errorf("found line %d key %q, want line 170 key '5'", bestIdx, best.Key)
	}
	assertSHA256(t, best.Plaintext, "8486b6576e42125994969e7233a3e90201c8efa18d17d4a4b24bdb53c8d96b58")
}
