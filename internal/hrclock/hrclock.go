// Package hrclock is a high-resolution monotonic clock for the timing attacks
// (challenges 31 and 32).
//
// On Windows, time.Now only advances every ~0.5 ms (it reads the interrupt
// time, not the performance counter), which is coarser than the leaks being
// measured. There Now reads QueryPerformanceCounter directly; elsewhere it
// simply uses time.Now, which already has nanosecond resolution.
package hrclock

import "time"

// Since returns the time elapsed since start, a value returned by Now.
func Since(start int64) time.Duration {
	return time.Duration(Now() - start)
}

// Spin busy-waits for d. Sleeping would be rounded up to the scheduler's
// timer resolution, far too coarse for sub-millisecond delays.
func Spin(d time.Duration) {
	for start := Now(); Since(start) < d; {
	}
}
