package set4_test

import (
	"testing"
	"time"
)

// Challenge 32 — Break HMAC-SHA1 with a slightly less artificial timing leak.
//
// Same server, but the per-byte delay is now 10× smaller (100 µs, versus
// 5 ms in the original challenge): the same order of magnitude as the
// jitter of a localhost HTTP round trip, so a single measurement per
// candidate no longer separates the right byte from the others. Repeating
// each measurement and ranking by the median — robust to the occasional
// scheduling hiccup, unlike the mean — restores the signal. Skipped with
// -short.
func TestChallenge32(t *testing.T) {
	if testing.Short() {
		t.Skip("timing attack takes about a minute")
	}
	breakTimingLeak(t, 100*time.Microsecond, 7)
}
