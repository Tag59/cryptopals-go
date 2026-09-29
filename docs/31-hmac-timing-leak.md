# Challenges 31–32 — HMAC-SHA1 timing leak

Code: [`set4/challenge31_test.go`](../set4/challenge31_test.go),
[`set4/challenge32_test.go`](../set4/challenge32_test.go)

## Setting

A web server (here an `httptest` server) answers

```
GET /test?file=passwd&signature=<hex>
```

with 200 if `signature == HMAC-SHA1(key, file)`, 500 otherwise. HMAC itself is
sound (see [length extension](29-length-extension.md)): the flaw is in how the
server compares the tags:

```go
for i := range a {
    if a[i] != b[i] {
        return false      // early exit
    }
    wait(delay)           // artificial per-byte cost
}
```

A signature whose first `n` bytes are right takes about `n × delay` longer to
be rejected. Goal: produce a valid signature for any file, without the key.

## The attack

Byte by byte: for position `i`, send the 256 signatures differing only in
byte `i` and keep the slowest one. That is 20 × 256 ≈ 5,000 requests instead
of 2^160 guesses.

What makes it work in practice:

- **Median, not mean.** Network and scheduling noise is one-sided (things are
  only ever *slower*) and bursty. Each candidate is measured several times, in
  interleaved rounds so that a burst spreads over all candidates, and scored by
  its median.
- **Re-rank the top.** A cheap first pass picks the 8 best candidates, which
  are then measured 5× more. A right byte hit by noise still gets its chance.
- **Wrong guesses are self-revealing.** Past a wrong byte, all 256 candidates
  take the same time: none stands out from the bulk. When the winner's lead
  drops below half of the usual lead, measure again, then step back one
  position. The last byte leaks nothing and is simply the one that gets a 200.

## Scaled-down delays

The original challenges wait 50 ms (31) and 5 ms (32) per byte, i.e. hours of
attack. The tests use 1 ms and 100 µs, which keeps the same spirit — 31 is
readable in one shot, 32 is at the level of a localhost round trip's jitter
and needs repeated measurements — while running in about a minute each. They
are skipped by `go test -short`.

Two practical gotchas surfaced along the way:

- On Windows, `time.Now()` only advances every ~0.5 ms — coarser than the leak
  itself. [`internal/hrclock`](../internal/hrclock) reads
  `QueryPerformanceCounter` there (and falls back to `time.Now` elsewhere).
- `time.Sleep` is rounded up to the timer resolution, so the server busy-waits
  instead.

## Takeaways

- **Compare secrets in constant time**: `hmac.Equal` /
  `subtle.ConstantTimeCompare`. A plain `bytes.Equal` or `==` on strings exits
  early too — without any artificial delay, but with enough samples remote
  timing differences down to about 100 ns have been measured across a LAN
  (Crosby, Wallach & Riedi, 2009).
- The leak turns an unforgeable 160-bit tag into a linear search. Statistics
  (medians, repetition, backtracking) beat noise much more easily than
  intuition suggests.
