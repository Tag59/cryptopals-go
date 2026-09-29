# Challenge 16 — CBC bit-flipping

Code: [`set2/challenge16_test.go`](../set2/challenge16_test.go)

## Setting

A web application stores user data in an encrypted cookie:

```
plaintext = "comment1=cooking%20MCs;userdata=" || escape(userdata) || ";comment2=…"
cookie    = AES-128-CBC_k,iv( PKCS#7(plaintext) )
```

`escape` turns `;` into `%3B` and `=` into `%3D`, so submitting
`;admin=true;` as userdata does nothing. When the cookie comes back, the server
decrypts it and grants admin rights if the plaintext contains `;admin=true;`.

Goal: become admin without knowing the key.

## Why CBC is malleable

CBC decryption of block `i` is:

```
P[i] = D_k(C[i]) ⊕ C[i−1]
```

`D_k(C[i])` is opaque to us, but the XOR with the previous ciphertext block is
fully linear. If we change `C[i−1]` into `C[i−1] ⊕ Δ`, then:

```
P'[i]   = D_k(C[i]) ⊕ C[i−1] ⊕ Δ = P[i] ⊕ Δ      (exactly controlled)
P'[i−1] = D_k(C[i−1] ⊕ Δ) ⊕ C[i−2]              (random garbage)
```

Flipping a bit in one ciphertext block flips **the same bit** in the next
plaintext block. The price is that block `i−1` decrypts to garbage.

## The attack

1. The prefix `comment1=cooking%20MCs;userdata=` is exactly 32 bytes (two
   blocks), so our userdata starts at block 2.
2. Submit 32 bytes of `A`: block 2 is a sacrificial block, block 3 is the one
   we will rewrite. Its plaintext `AAAAAAAAAAAAAAAA` is known.
3. Choose the target plaintext for block 3: `;admin=true;AAAA`.
4. Compute `Δ = "AAAAAAAAAAAAAAAA" ⊕ ";admin=true;AAAA"` and XOR it into the
   ciphertext block 2.
5. Send the modified cookie. Block 2 decrypts to garbage, which only
   overwrites our own userdata. Block 3 decrypts to `;admin=true;AAAA`. The
   padding at the end is untouched, so it is still valid.

The escaping step never sees the `;` and `=`: they are never in the plaintext
we submit, they only appear after decryption.

## Takeaways

- **Encryption does not provide integrity.** CBC, CTR (challenge 26) and every
  other unauthenticated mode let an attacker make controlled changes to the
  plaintext.
- Input sanitisation before encryption cannot protect what happens to the
  ciphertext afterwards.
- Fix: use an AEAD (AES-GCM, ChaCha20-Poly1305), or encrypt-then-MAC with a
  separate key, and verify the tag **before** decrypting or parsing anything.
