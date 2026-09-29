package hrclock

import (
	"testing"
	"time"
)

// The clock must be monotonic and resolve well below the 100 µs leak of
// challenge 32.
func TestResolution(t *testing.T) {
	smallest := time.Hour
	prev := Now()
	for range 100000 {
		now := Now()
		if now < prev {
			t.Fatalf("clock went backwards: %d then %d", prev, now)
		}
		if d := time.Duration(now - prev); d > 0 && d < smallest {
			smallest = d
		}
		prev = now
	}
	if smallest > 10*time.Microsecond {
		t.Errorf("smallest observable step is %v, want <= 10µs", smallest)
	}
}

func TestSpin(t *testing.T) {
	start := Now()
	Spin(200 * time.Microsecond)
	if d := Since(start); d < 200*time.Microsecond || d > 20*time.Millisecond {
		t.Errorf("Spin(200µs) took %v", d)
	}
}
