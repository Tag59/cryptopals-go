# Set 3 — Block & stream crypto

**Goal of the set:** two themes. First, one of the most important real-world
attacks, the **CBC padding oracle**. Then **stream ciphers**: CTR mode, what
happens when its nonce is reused, and why a non-cryptographic random number
generator (MT19937) must never produce keys, seeds or tokens.

```sh
go test -v ./set3/
```

## What gets built

| Tool | Where |
|------|-------|
| CTR mode (keystream = AES of a nonce/counter) | [`internal/aesutil/ctr.go`](../internal/aesutil/ctr.go) |
| Many-time pad breaker (column-wise frequency analysis) | [`internal/freq/manytime.go`](../internal/freq/manytime.go) |
| MT19937 generator, tempering and its inverse | [`internal/mt19937`](../internal/mt19937) |

## Part 1 — Padding oracle

### 17 · The CBC padding oracle — *the set's centrepiece*
The server only answers "padding valid / invalid". **How:** CBC gives
`plaintext = D(C) ⊕ P` for a block `C` and its predecessor `P`. Send a forged
`P'` and try its last byte until the padding is valid: that means the last
byte decrypts to `0x01`, which reveals `D(C)`'s last byte. Move on to `0x02 0x02`,
and so on, then XOR with the real `P`. At most 256 queries per byte.
**Why it matters:** one bit of error information is enough to decrypt
everything. Real-world attacks (ASP.NET, Lucky Thirteen, POODLE) share this
root cause.
Write-up: [docs/17-cbc-padding-oracle.md](../docs/17-cbc-padding-oracle.md)

## Part 2 — CTR and nonce reuse

### 18 · Implement CTR
Encrypt a counter, XOR the result with the data: a stream cipher built from a
block cipher. No padding, random access, and encryption is its own inverse.
The one hard rule: **never reuse a (key, nonce) pair**.

### 19 · Break fixed-nonce CTR with substitutions
Forty lines encrypted with the same key *and* nonce share one keystream: a
many-time pad. **How:** each column is a single-byte XOR (Set 1, challenge 3);
where statistics are too thin (first column, long tails), fix things by hand
— capital letters at line start, then guess a plausible end of the longest
line ("crib") to get the keystream there, and check that all other lines
become readable.

### 20 · Break fixed-nonce CTR statistically
**How:** truncate all ciphertexts to the shortest length `L` and concatenate
them: it becomes a repeating-key XOR with key size `L`, which Set 1 challenge
6 already breaks.
**Why it matters (19–20):** a reused nonce turns a modern cipher into a
Vigenère cipher.

## Part 3 — MT19937, a PRNG that is not a CSPRNG

### 21 · Implement MT19937
The Mersenne Twister, used by default in Python's `random`, PHP's `mt_rand`,
C++'s `std::mt19937`. Statistically excellent, fully determined by a 624-word
state.

### 22 · Crack an MT19937 seed
Seeded with the current time. **How:** try every timestamp in a plausible
window and keep the one that reproduces the output (the clock is simulated so
the test is instant).
**Why it matters:** a seed has the entropy of its source — a timestamp has
almost none.

### 23 · Clone an MT19937 from its output
**How:** each output is `temper(state[i])`, and tempering is invertible
(shifts and XORs undone step by step). 624 outputs give the whole state, hence
every future output.
**Why it matters:** "random" tokens or nonces from a non-cryptographic PRNG are
predictable after enough observations.

### 24 · MT19937 stream cipher
**How:** a 16-bit key is 65,536 candidates — brute-force it from a few bytes of
known plaintext. Then recognise a password-reset token generated from a
time-seeded MT19937 by regenerating candidate tokens for recent timestamps.

## Takeaways

- **Error messages are an attack surface.** Authenticate before decrypting,
  and fail uniformly.
- **Nonces are not optional.** In CTR (and GCM), one reuse leaks the XOR of
  plaintexts.
- **Use a CSPRNG** (`crypto/rand`) for anything secret: keys, IVs, seeds,
  tokens.

Previous: [Set 2](../set2/README.md) · Next: [Set 4 — Stream crypto and randomness](../set4/README.md)
