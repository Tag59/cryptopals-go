package hrclock

import (
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	qpf      = kernel32.NewProc("QueryPerformanceFrequency")
	freq     = func() int64 {
		var f int64
		qpf.Call(uintptr(unsafe.Pointer(&f)))
		return f
	}()
)

// Now returns a monotonic timestamp in nanoseconds.
func Now() int64 {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	// Split the conversion so that c * 1e9 cannot overflow.
	return c/freq*1e9 + c%freq*1e9/freq
}
