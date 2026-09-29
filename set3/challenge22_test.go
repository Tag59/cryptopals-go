package set3_test

import (
	mrand "math/rand/v2"
	"testing"
	"time"

	"github.com/Tag59/cryptopals-go/internal/mt19937"
)

// Challenge 22 — Crack an MT19937 seed.
//
// A program waits a random 40-1000 s, seeds MT19937 with the current Unix
// time, waits again, and prints the first output. A timestamp is not a secret:
// it lives in a window of a few thousand values around "now". The attacker
// tries every second in that window as a seed and keeps the one reproducing
// the observed output.
//
// The statement asks for real sleeps; we simulate the clock instead so the
// test runs instantly and deterministically. The attack is identical.
//
// Lesson: a seed must come from a CSPRNG, never from the time, a PID or a
// counter. Its entropy is the entropy of everything derived from it.
func TestChallenge22(t *testing.T) {
	const window = 2 * 1000 // covers both random waits of at most 1000 s

	for trial := range 10 {
		now := time.Now().Unix()
		now += 40 + mrand.Int64N(961)
		seed := uint32(now)
		output := mt19937.New(seed).Uint32()
		now += 40 + mrand.Int64N(961)

		got, ok := crackTimeSeed(output, now, window)
		if !ok {
			t.Fatalf("trial %d: seed not found in the last %d seconds", trial, window)
		}
		if got != seed {
			t.Errorf("trial %d: recovered seed %d, want %d", trial, got, seed)
		}
	}
}

// crackTimeSeed searches the timestamps in [now-window, now] for the seed
// whose first MT19937 output equals output.
func crackTimeSeed(output uint32, now, window int64) (uint32, bool) {
	for ts := now; ts >= now-window; ts-- {
		if mt19937.New(uint32(ts)).Uint32() == output {
			return uint32(ts), true
		}
	}
	return 0, false
}
