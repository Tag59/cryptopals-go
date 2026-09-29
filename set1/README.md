# Set 1 — Basics

**Goal of the set:** get comfortable handling raw bytes, then break the oldest
trick in the book — XOR "encryption" — with nothing but statistics. The set
ends by introducing AES and its most naive mode, ECB, and showing that it leaks
structure without any key.

```sh
go test -v ./set1/
```

## What gets built

| Tool | Where | Used again in |
|------|-------|---------------|
| hex / base64 conversions, XOR, Hamming distance | [`internal/xorutil`](../internal/xorutil) | everywhere |
| English scoring, single-byte and repeating-key XOR breakers | [`internal/freq`](../internal/freq) | challenges 19–20 (fixed-nonce CTR) |
| AES-ECB built by hand on top of the raw block function | [`internal/aesutil`](../internal/aesutil) | every AES challenge |

## The challenges

### 1–2 · Hex, base64 and XOR
Pure plumbing: decode to bytes, work on bytes, re-encode only for display. XOR
matters because it is its own inverse (`a ⊕ b ⊕ b = a`): it is the core of
every stream cipher and of most attacks later on.

### 3 · Single-byte XOR
**How:** a single-byte key has only 256 values. Decrypt with all of them and
keep the result that looks most like English (letter and space frequencies,
heavy penalty for control characters).
**Why it matters:** if you can enumerate the keyspace, there is no keyspace.

### 4 · Detect single-character XOR
**How:** run the challenge 3 attack on every line of a file. The one line that
was really encrypted scores far above the random ones.
**Why it matters:** the same score is both a decryptor and a *distinguisher*.

### 5 · Repeating-key XOR
A byte-level Vigenère cipher. Its weakness: every `len(key)`-th byte is XORed
with the same key byte.

### 6 · Break repeating-key XOR — *the set's centrepiece*
**How:**
1. **Key size** — for each candidate size `k`, compare consecutive `k`-byte
   blocks by Hamming distance. With the right `k` the key cancels out
   (`c1 ⊕ c2 = p1 ⊕ p2`), and English differs in fewer bits than random bytes,
   so the right `k` gives the smallest normalised distance.
2. **Transpose** — gather every `k`-th byte into `k` columns; each column is a
   single-byte XOR.
3. **Solve each column** as in challenge 3 and reassemble the key.

**Why it matters:** reusing key material turns one long key into many tiny,
individually breakable ones. The same idea returns in Set 3 against CTR with
a reused nonce.

### 7 · AES in ECB mode
No attack yet: ECB is implemented by hand from the raw AES block to understand
what a *mode of operation* is. ECB encrypts each 16-byte block independently —
which is exactly its flaw.

### 8 · Detect AES in ECB mode
**How:** ECB is deterministic per block, so identical plaintext blocks give
identical ciphertext blocks. Among 204 ciphertexts, the ECB one is the only one
containing repeated blocks.
**Why it matters:** ECB leaks the *structure* of the plaintext (the famous "ECB
penguin"), with no key involved. Set 2 turns this leak into full decryption.

## Takeaways

- Work on bytes, never on strings or encodings.
- "Secret" is not "secure": a small or reused key falls to plain frequency
  analysis.
- A strong primitive (AES) can be used in a weak way (ECB). Most of Cryptopals
  is about *misused* primitives, not broken ones.

Next: [Set 2 — Block crypto](../set2/README.md)
