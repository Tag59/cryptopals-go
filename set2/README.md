# Set 2 — Block crypto

**Goal of the set:** move from "breaking ciphers" to "breaking *systems* that
use a block cipher". The attacker now talks to a server (an *oracle*) that
encrypts or decrypts data partly under their control. AES itself is never
attacked: every attack exploits how ECB and CBC are used, with no integrity
protection.

```sh
go test -v ./set2/
```

## What gets built

| Tool | Where |
|------|-------|
| PKCS#7 padding, strict unpadding | [`internal/aesutil/pkcs7.go`](../internal/aesutil/pkcs7.go) |
| CBC mode built by hand, cross-checked against `crypto/cipher` | [`internal/aesutil/cbc.go`](../internal/aesutil/cbc.go) |

## The challenges

### 9 · PKCS#7 padding
Pad with `n` bytes of value `n`. A full block is added when the input is
already aligned, so the last byte always says how much to strip.

### 10 · CBC mode
Each plaintext block is XORed with the previous ciphertext block before
encryption: `C[i] = E(P[i] ⊕ C[i−1])`. Identical plaintext blocks no longer
produce identical ciphertext blocks — the fix for challenge 8's leak.

### 11 · ECB/CBC detection oracle
**How:** the attacker chooses the input. Three blocks of the same byte
guarantee at least two identical aligned blocks, whatever the random prefix.
Identical output blocks ⇒ ECB.
**Why it matters:** a chosen-plaintext capability turns a small leak into a
reliable fingerprint. It is the first step of challenge 12.

### 12 · Byte-at-a-time ECB decryption — *the set's centrepiece*
The server returns `ECB(attacker_input || secret)`.
**How:** grow the input until the ciphertext length jumps, which reveals the
block size and the secret length. Then send `bs − 1` filler bytes so that
exactly one unknown secret byte falls at the end of a block; compare that block against a dictionary of the
256 possible values. Slide by one byte and repeat.
**Why it matters:** at most 256 queries per byte instead of 2¹²⁸ per block —
the secret is recovered without ever touching the key.
Write-up: [docs/12-byte-at-a-time-ecb.md](../docs/12-byte-at-a-time-ecb.md)

### 13 · ECB cut-and-paste
**How:** ECB blocks are independent, so ciphertext blocks from different
messages can be spliced. Craft emails so that `admin` + valid padding fills a
block, and so that `role=` ends on a block boundary, then paste one into the
other.
**Why it matters:** encryption is not integrity. The server decrypts a
message nobody ever encrypted.

### 14 · Byte-at-a-time ECB decryption (harder)
Same as 12 with a random-length prefix in front. **How:** find the prefix
length (pad until two identical filler blocks appear, with two different
filler bytes to avoid an edge case), then wrap the oracle so it looks exactly
like challenge 12's and reuse that attack unchanged.

### 15 · PKCS#7 padding validation
Check *every* padding byte. Correct in itself — but once its result is
observable remotely, it becomes the padding oracle of challenge 17.

### 16 · CBC bit-flipping
**How:** CBC decryption computes `P[i] = D(C[i]) ⊕ C[i−1]`. XORing a value
into ciphertext block `i−1` XORs the same value into plaintext block `i`
(block `i−1` becomes garbage). This writes `;admin=true;` past the server's
escaping.
**Why it matters:** CBC gives confidentiality, not integrity; unauthenticated
ciphertext is malleable.
Write-up: [docs/16-cbc-bitflipping.md](../docs/16-cbc-bitflipping.md)

## Takeaways

- **ECB is never acceptable**: it leaks equality of blocks, lets an attacker
  decrypt secrets placed next to their input, and lets them rearrange messages.
- **CBC fixes confidentiality, not integrity**: flipped bits propagate
  predictably.
- The common fix for all of it: an **AEAD** (AES-GCM, ChaCha20-Poly1305) or
  encrypt-then-MAC, so that any tampered ciphertext is rejected before
  decryption.

Previous: [Set 1](../set1/README.md) · Next: [Set 3 — Block & stream crypto](../set3/README.md)
