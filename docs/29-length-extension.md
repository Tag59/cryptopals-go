# Challenges 29–30 — Length extension on a secret-prefix MAC

Code: [`set4/challenge29_test.go`](../set4/challenge29_test.go),
[`set4/challenge30_test.go`](../set4/challenge30_test.go),
hashes in [`internal/mdhash`](../internal/mdhash)

## Setting

A server authenticates messages with the "obvious" keyed hash:

```
tag = SHA1(key || message)
```

It hands out the tag of

```
comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
```

and accepts any `(message, tag)` pair where the tag matches. Goal: get a
message ending with `;admin=true` accepted, without knowing the key (nor even
its length).

## Why Merkle–Damgård hashes leak their state

SHA-1 and MD4 pad the message, cut it into 64-byte blocks and run a
compression function block after block over a small state (5 words for SHA-1,
4 for MD4):

```
h0 = IV
h[i+1] = compress(h[i], block[i])
digest = h[n]               ← the final state, serialised
```

The digest *is* the internal state. Anyone holding `SHA1(X)` can set the state
to it and keep compressing more blocks, obtaining the hash of a longer message
that starts with `X` — without knowing `X` itself.

The only catch is that the longer message must contain the padding SHA-1
appended to `X` (the "glue"): `0x80`, zeros, then the length of `X` in bits.
It depends only on `len(X) = len(key) + len(message)`.

## The attack

For each guess of the key length `k`:

```
glue   = padding(k + len(message))
forged = message || glue || ";admin=true"
tag'   = resume(state = tag, already hashed = k + len(message) + len(glue),
                data = ";admin=true")
```

`tag'` equals `SHA1(key || forged)`, so the server accepts `(forged, tag')` as
soon as `k` is right. At most a few dozen queries. The glue bytes are ugly
(`\x80\x00…\x02\x98`) but most parsers ignore them, and `;admin=true` ends up
at the end.

`internal/mdhash` implements SHA-1 and MD4 from scratch precisely to expose
`SHA1Resume` / `MD4Resume`, which the standard library (rightly) does not
offer. MD4 (challenge 30) is the same attack: only the state size and the
endianness of words and length change.

## Takeaways

- **`H(key || m)` is not a MAC** for SHA-1, SHA-256, MD4, MD5 — every
  Merkle–Damgård hash. (SHA-3 and BLAKE2/3 are not vulnerable, but there is no
  reason to hand-roll anyway.)
- **Use HMAC**: `H(K ⊕ opad || H(K ⊕ ipad || m))`. The tag is the state of the
  *outer* hash, which never saw the message; extending it gets you nothing.
- Real-world case: the 2009 Flickr API signature forgery.
