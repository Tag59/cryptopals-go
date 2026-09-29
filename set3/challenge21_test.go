package set3_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/mt19937"
)

// Challenge 21 — Implement the MT19937 Mersenne Twister RNG.
// Implementation in internal/mt19937, checked there against the reference C
// implementation and the C++ standard's known answer. The generator is fully
// deterministic given its 624-word state, which the next challenges exploit.
func TestChallenge21(t *testing.T) {
	mt := mt19937.New(5489)
	want := []uint32{3499211612, 581869302, 3890346734, 3586334585, 545404204}
	for i, w := range want {
		if got := mt.Uint32(); got != w {
			t.Errorf("output %d = %d, want %d", i, got, w)
		}
	}
}
