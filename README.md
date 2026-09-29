# cryptopals-go

[![CI](https://github.com/Tag59/cryptopals-go/actions/workflows/ci.yml/badge.svg)](https://github.com/Tag59/cryptopals-go/actions/workflows/ci.yml)

Solutions to the [Cryptopals Crypto Challenges](https://cryptopals.com/) (Sets 1–4) in Go,
using only the standard library. Every challenge is an executable, self-verifying test.

> [!WARNING]
> **Educational project — do not reuse this code in production.**
> The goal here is to *break* cryptographic primitives that are used incorrectly
> (ECB mode, unauthenticated CBC, nonce reuse, naive keyed MACs, non-constant-time
> comparisons…) in order to understand *why* the real-world rules exist.
> Helpers in `internal/` deliberately expose low-level building blocks and skip the
> safeguards a real library must have. For real systems, use vetted high-level
> constructions (e.g. AES-GCM or ChaCha20-Poly1305 via `crypto/cipher`, `crypto/hmac`,
> `crypto/subtle`) and audited libraries.

## Running

```sh
go test ./...          # every challenge
go test -v ./set1/     # one set, verbose
go test -run Challenge06 -v ./set1/
```

Expected plaintexts are pinned by **SHA-256 digest** rather than written out in clear,
so the tests stay spoiler-free while still failing on any regression.

## Layout

| Path               | Content                                                        |
|--------------------|----------------------------------------------------------------|
| `internal/xorutil` | XOR primitives, hex/base64 conversions, Hamming distance        |
| `internal/freq`    | English frequency scoring, single-byte & repeating-key XOR breaking |
| `internal/aesutil` | AES block modes built by hand (ECB, CBC, CTR), PKCS#7           |
| `internal/mt19937` | MT19937 Mersenne Twister PRNG (to be cloned and cracked)       |
| `internal/mdhash`  | SHA-1 (resumable, for length extension)                        |
| `internal/testutil`| Shared test helpers (fixtures decoding, pinned SHA-256 answers) |
| `setN/`            | One `challengeNN_test.go` per challenge, data in `setN/testdata` |
| `docs/`            | Write-ups for the flagship attacks                              |

## Progress

### Set 1 — Basics

| #  | Challenge                                   | Status |
|----|---------------------------------------------|--------|
| 1  | Convert hex to base64                       | ✅ |
| 2  | Fixed XOR                                   | ✅ |
| 3  | Single-byte XOR cipher                      | ✅ |
| 4  | Detect single-character XOR                 | ✅ |
| 5  | Implement repeating-key XOR                 | ✅ |
| 6  | Break repeating-key XOR                     | ✅ |
| 7  | AES in ECB mode                             | ✅ |
| 8  | Detect AES in ECB mode                      | ✅ |

### Set 2 — Block crypto

| #  | Challenge                                   | Status |
|----|---------------------------------------------|--------|
| 9  | Implement PKCS#7 padding                    | ✅ |
| 10 | Implement CBC mode                          | ✅ |
| 11 | An ECB/CBC detection oracle                 | ✅ |
| 12 | Byte-at-a-time ECB decryption (Simple)      | ✅ |
| 13 | ECB cut-and-paste                           | ✅ |
| 14 | Byte-at-a-time ECB decryption (Harder)      | ✅ |
| 15 | PKCS#7 padding validation                   | ✅ |
| 16 | CBC bitflipping attacks                     | ✅ |

### Set 3 — Block & stream crypto

| #  | Challenge                                   | Status |
|----|---------------------------------------------|--------|
| 17 | The CBC padding oracle                      | ✅ |
| 18 | Implement CTR, the stream cipher mode       | ✅ |
| 19 | Break fixed-nonce CTR mode using substitutions | ✅ |
| 20 | Break fixed-nonce CTR statistically         | ✅ |
| 21 | Implement the MT19937 Mersenne Twister RNG  | ✅ |
| 22 | Crack an MT19937 seed                       | ✅ |
| 23 | Clone an MT19937 RNG from its output        | ✅ |
| 24 | Create the MT19937 stream cipher and break it | ✅ |

### Set 4 — Stream crypto and randomness

| #  | Challenge                                   | Status |
|----|---------------------------------------------|--------|
| 25 | Break "random access read/write" AES CTR    | ✅ |
| 26 | CTR bitflipping                             | ✅ |
| 27 | Recover the key from CBC with IV=Key        | ✅ |
| 28 | Implement a SHA-1 keyed MAC                 | ✅ |
| 29 | Break a SHA-1 keyed MAC using length extension | ✅ |
| 30 | Break an MD4 keyed MAC using length extension | ⬜ |
| 31 | Implement and break HMAC-SHA1 with an artificial timing leak | ⬜ |
| 32 | Break HMAC-SHA1 with a slightly less artificial timing leak | ⬜ |

## Credits

Challenge statements and data files (`setN/testdata/`) belong to their authors
(cryptopals.com, originally NCC Group).
