//go:build !windows

package hrclock

import "time"

var origin = time.Now()

// Now returns a monotonic timestamp in nanoseconds.
func Now() int64 {
	return int64(time.Since(origin))
}
