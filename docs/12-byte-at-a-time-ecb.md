# Challenge 12 — Byte-at-a-time ECB decryption

Code: [`set2/challenge12_test.go`](../set2/challenge12_test.go)

## Setting

A server encrypts, under a fixed secret key, the concatenation of data we
control and a secret it wants to keep:

```
ciphertext = AES-128-ECB_k( attacker_input || secret || PKCS#7 padding )
```

We can call this oracle as often as we like. We never see the key. Goal:
recover `secret`.

This is not academic: any system that encrypts a user-supplied field next to a
secret field (a token, a cookie value, an API key) with a deterministic
cipher has this shape.

## Why ECB is the problem

ECB encrypts every 16-byte block independently with the same key. It is a
deterministic codebook: **same plaintext block ⇒ same ciphertext block**. If we
can arrange for a block to contain 15 bytes we know and 1 byte we do not, the
codebook only has 256 possible entries for that block — and we can compute all
of them by asking the oracle.

## The attack

### 1. Block size and secret length

Send inputs of growing length `n = 0, 1, 2, …` and watch the ciphertext length.
It stays constant, then jumps by exactly one block. The size of the jump is the
block size (16). The jump happens when `n + len(secret)` fills whole blocks,
forcing a full block of padding, so:

```
len(secret) = len(ciphertext for n = 0) − n_jump
```

### 2. Confirm ECB

Send 48 identical bytes; ECB yields two identical ciphertext blocks
(challenge 11).

### 3. Recover one byte

Send 15 filler bytes. The first plaintext block becomes:

```
| A A A A A A A A A A A A A A A s0 |  s1 s2 s3 …
```

Record its ciphertext block. Then, for each `c` in 0..255, send
`AAAAAAAAAAAAAAA || c` and compare the first ciphertext block. Exactly one `c`
matches: it is `s0`.

### 4. Slide the window

Send 14 fillers: the first block is `A×14 || s0 || s1`. We know `s0`, so again
only one byte is unknown. Build the dictionary with
`A×14 || s0 || c` and match. Keep going: once the known part exceeds one
block, target the block that holds the next unknown byte, and use the last 15
known bytes (fillers + recovered secret) as the dictionary prefix.

```
k = number of bytes already recovered
filler  = 'A' × (15 − k mod 16)
target  = block ⌊k / 16⌋ of oracle(filler)
window  = last 15 bytes of (filler || recovered)
secret[k] = the c such that oracle(window || c)[0:16] == target
```

## Cost

At most `256 + 1` queries per secret byte, so ~35,000 queries for the 138-byte
secret here: the test runs in milliseconds. Brute-forcing a single AES block
would need 2^128 tries: the attack turns an impossible search into 16
independent 8-bit searches per block.

## Takeaways

- **Never use ECB.** Determinism at the block level is enough to break
  confidentiality as soon as an attacker controls part of the plaintext.
- More generally, a deterministic encryption of `attacker data || secret` is a
  decryption oracle for the secret. Use a randomised, authenticated mode
  (AES-GCM, ChaCha20-Poly1305) with a fresh nonce per message.
- The same "one unknown byte at a time" idea reappears in the CBC padding
  oracle (challenge 17) and in compression side channels (CRIME/BREACH).
