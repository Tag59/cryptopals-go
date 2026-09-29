# Set 4 — Stream crypto and randomness

**Goal of the set:** finish off unauthenticated encryption (CTR is even more
malleable than CBC), then move to **message authentication**: build the naive
keyed-hash MAC, break it with length extension, build HMAC properly — and
break it anyway through a timing leak in how the tag is *compared*.

```sh
go test -v ./set4/
go test -short ./set4/   # skips the timing attacks (31–32, about a minute each)
```

## What gets built

| Tool | Where |
|------|-------|
| SHA-1 and MD4 from scratch, resumable from any digest | [`internal/mdhash`](../internal/mdhash) |
| HMAC-SHA1 (RFC 2104), cross-checked against `crypto/hmac` | [`internal/mdhash/hmac.go`](../internal/mdhash/hmac.go) |
| High-resolution clock (Windows' `time.Now` ticks every ~0.5 ms) | [`internal/hrclock`](../internal/hrclock) |

## Part 1 — Last blows to unauthenticated encryption

### 25 · Break "random access read/write" AES-CTR
The server offers an `edit(offset, newtext)` API. **How:** edit the whole
ciphertext with *itself*: the server re-encrypts it with the same keystream,
returning `C ⊕ KS = P`.
**Why it matters:** any API that re-encrypts at the same counter reuses the
keystream.

### 26 · CTR bit-flipping
Challenge 16 again, with CTR. **How:** `C[i] = P[i] ⊕ KS[i]`, so
`C'[i] = C[i] ⊕ P[i] ⊕ P'[i]` writes any chosen byte, with no garbled block.
**Why it matters:** stream ciphers are perfectly malleable.

### 27 · Recover the key from CBC with IV = key
**How:** send `C1 || 0 || C1`. The receiver rejects the non-ASCII result and
echoes the plaintext in its error: `P'1 ⊕ P'3 = D(C1) ⊕ K ⊕ D(C1) = K`.
**Why it matters:** the IV must be random and independent of the key, and
errors must never echo decrypted data.

## Part 2 — MACs and length extension

### 28 · SHA-1 keyed MAC
The "obvious" MAC: `SHA1(key || message)`. SHA-1 is implemented from scratch
to expose its internal state. Tampering with the message or the tag is
rejected… so far.

### 29 · Break it with length extension — *first centrepiece*
**How:** SHA-1's digest *is* its internal state after the last block. Resume
hashing from the tag and get `SHA1(key || msg || glue || ";admin=true")`
without the key; `glue` (the original padding) depends only on the length,
so just try each key length.

### 30 · Same attack on MD4
Same Merkle–Damgård structure; only the state size and endianness change.

**Why it matters (28–30):** `H(key || m)` is not a MAC. HMAC exists
precisely to defeat this.
Write-up: [docs/29-length-extension.md](../docs/29-length-extension.md)

## Part 3 — Timing attacks

### 31 · HMAC-SHA1 with an artificial timing leak — *second centrepiece*
HMAC is sound, but the web server compares tags byte by byte, exits at the
first mismatch and wastes time on each matching byte. **How:** for each
position, time the 256 candidates and keep the slowest: 20 × 256 requests
instead of 2¹⁶⁰.

### 32 · A slightly less artificial leak
The per-byte leak is now on the order of network jitter. **How:** measure
each candidate several times and rank by median, re-measure the best ones,
and step back when no candidate stands out (the sign of an earlier wrong
byte).

**Why it matters (31–32):** secrets must be compared in constant time
(`hmac.Equal`, `subtle.ConstantTimeCompare`). The delays are scaled down from
the original statement (1 ms and 100 µs instead of 50 ms and 5 ms) so the tests
run in minutes, not hours.
Write-up: [docs/31-hmac-timing-leak.md](../docs/31-hmac-timing-leak.md)

## Takeaways

- **Confidentiality without integrity is worthless** against an active
  attacker — CBC or CTR, same story. Use an AEAD.
- **Don't build MACs from bare hashes**: use HMAC (or a hash designed for
  it: SHA-3/KMAC, BLAKE2/3 keyed mode).
- **A correct primitive can leak through its implementation.** Compare
  secrets in constant time.

Previous: [Set 3](../set3/README.md)
