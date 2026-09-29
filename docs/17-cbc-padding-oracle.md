# Challenge 17 — The CBC padding oracle

Code: [`set3/challenge17_test.go`](../set3/challenge17_test.go)

## Setting

A server hands out tokens encrypted with AES-128-CBC under a secret key
(random IV, PKCS#7 padding). When it receives a token back, it decrypts it and
behaves differently depending on whether the padding was valid: a distinct
error message, HTTP status code, or even response time.

The attacker can submit any `(IV, ciphertext)` pair and learn **one bit** per
query: padding valid or not. Goal: decrypt the token.

This is the attack published by Vaudenay in 2002. It broke ASP.NET (2010), led
to Lucky Thirteen against TLS (2013) and POODLE against SSLv3 (2014).

## Key observation

CBC decryption of a block `C` with predecessor `P` (the previous ciphertext
block, or the IV for the first block) is:

```
plaintext = I ⊕ P      where I = D_k(C) is the "intermediate" block
```

We cannot compute `I`, but we choose `P`. If we send `(P', C)`, the server
computes `I ⊕ P'` and checks its padding. So the oracle tells us whether
`I ⊕ P'` ends with a valid PKCS#7 padding, for any `P'` we pick. Once we know
`I`, the real plaintext is `I ⊕ P`.

## Recovering `I` byte by byte

**Last byte.** Try the 256 values of `P'[15]`. The padding is valid when the
last plaintext byte is `0x01`, i.e. `I[15] ⊕ P'[15] = 0x01`, so:

```
I[15] = P'[15] ⊕ 0x01
```

**Next bytes.** To attack byte 14 we want the plaintext to end with
`02 02`. We know `I[15]`, so we set `P'[15] = I[15] ⊕ 0x02`, then try the 256
values of `P'[14]`. A valid padding means `I[14] = P'[14] ⊕ 0x02`. We continue
with padding `03 03 03`, and so on down to byte 0.

```
for pos = 15 down to 0:
    pad = 16 − pos
    P'[k] = I[k] ⊕ pad          for all k > pos   (known tail)
    find g such that oracle(P' with P'[pos] = g, C) is valid
    I[pos] = g ⊕ pad
```

Each block is attacked independently, using only the block itself and a
forged IV, so the whole ciphertext can be decrypted, including the first block
(the real IV is only needed for the final XOR).

## The edge case on the last byte

When attacking byte 15, a valid padding usually means the plaintext ends with
`0x01`. But if the plaintext happens to end with `?? 02` and our guess makes
the last byte `0x02`, the padding `02 02` is also valid, and we would deduce a
wrong `I[15]`.

To tell the two apart, flip byte 14 of `P'` and ask again. A genuine `01`
padding does not depend on byte 14 and stays valid; an accidental `02 02`
breaks. The test `TestRecoverIntermediateAccidentalPadding` forces this case
(it only occurs about once in 256 blocks otherwise) and fails if the check is
removed.

## Cost

At most 256 queries per byte, about 128 on average: roughly 2,000 queries per
16-byte block. In the test, each of the 10 strings (35 to 60 bytes) is
recovered in 5,000 to 8,000 queries.

## Takeaways

- **Every observable difference in failure modes is an oracle.** Returning the
  same error message is not enough if timing still differs (Lucky Thirteen).
- **Authenticate before decrypting.** With encrypt-then-MAC or an AEAD
  (AES-GCM, ChaCha20-Poly1305), a forged ciphertext is rejected before any
  padding is examined, and the oracle disappears.
- Padding validation from challenge 15 was correct; the vulnerability comes
  from exposing its result to an attacker.
