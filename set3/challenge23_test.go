package set3_test

import (
	mrand "math/rand/v2"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/mt19937"
)

// Challenge 23 — Clone an MT19937 RNG from its output.
//
// Each output is Temper(state[i]), and tempering is a bijection built from
// four steps of the form y ^= (y >> s) or y ^= (y << s) & mask. Each step can
// be undone, so every output reveals one raw state word. MT19937 has 624
// state words: 624 consecutive outputs (aligned on a twist) give the whole
// state, and from there every future output.
//
// Lesson: a statistically excellent PRNG can be perfectly predictable. Session
// tokens, password reset links or nonces drawn from MT19937 (PHP mt_rand,
// Python random) can be forged once enough outputs have been observed.
func TestChallenge23(t *testing.T) {
	victim := mt19937.New(mrand.Uint32())

	var state [mt19937.StateSize]uint32
	for i := range state {
		state[i] = untemper(victim.Uint32())
	}
	clone := mt19937.FromState(state)

	for i := range 1000 {
		if got, want := clone.Uint32(), victim.Uint32(); got != want {
			t.Fatalf("prediction %d: clone gave %d, victim gave %d", i, got, want)
		}
	}
}

func TestUntemperInvertsTemper(t *testing.T) {
	for _, y := range append([]uint32{0, 1, 0xffffffff, 0x80000000}, randomWords(10000)...) {
		if got := untemper(mt19937.Temper(y)); got != y {
			t.Fatalf("untemper(Temper(%#x)) = %#x", y, got)
		}
	}
}

func randomWords(n int) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = mrand.Uint32()
	}
	return out
}

// untemper inverts mt19937.Temper by undoing its four steps in reverse order.
func untemper(y uint32) uint32 {
	y = undoRightShiftXor(y, 18)
	y = undoLeftShiftXorMask(y, 15, 0xefc60000)
	y = undoLeftShiftXorMask(y, 7, 0x9d2c5680)
	y = undoRightShiftXor(y, 11)
	return y
}

// undoRightShiftXor solves y = x ^ (x >> s) for x. The top s bits of x equal
// those of y; each iteration of x = y ^ (x >> s) then fixes s more bits, so
// ceil(32/s) - 1 iterations recover all 32.
func undoRightShiftXor(y uint32, s uint) uint32 {
	x := y
	for range 32 / s {
		x = y ^ x>>s
	}
	return x
}

// undoLeftShiftXorMask solves y = x ^ ((x << s) & mask) for x, fixing s more
// low-order bits per iteration.
func undoLeftShiftXorMask(y uint32, s uint, mask uint32) uint32 {
	x := y
	for range 32 / s {
		x = y ^ x<<s&mask
	}
	return x
}
