package set2_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/testutil"
)

// Challenge 12 — Byte-at-a-time ECB decryption (Simple).
//
// The oracle computes ECB_k(attacker-input || secret). We recover the secret
// one byte at a time, with no knowledge of the key. Full write-up in
// docs/12-byte-at-a-time-ecb.md.
//
//  1. Block size: grow the input until the ciphertext length jumps; the jump
//     is the block size. The same jump gives the secret length.
//  2. Confirm ECB (challenge 11 detector).
//  3. Send bs-1 filler bytes: the first block is filler + secret[0]. Build a
//     dictionary of E(filler + c) for all 256 c; the match reveals secret[0].
//     Shorten the filler by one and repeat, sliding the known bytes in so that
//     each target block always has exactly one unknown byte.
//
// Cost: at most 256 queries per secret byte instead of 2^128 per block.
// Lesson: ECB + attacker-controlled data next to a secret = plaintext recovery.
func TestChallenge12(t *testing.T) {
	secret := testutil.ReadBase64File(t, "testdata/12.txt")
	oracle := newSuffixOracle(t, aesutil.RandomBytes(16), nil, secret)

	got, err := byteAtATimeECB(oracle)
	if err != nil {
		t.Fatalf("byteAtATimeECB: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("recovered %d bytes that do not match the %d-byte secret", len(got), len(secret))
	}
}

// newSuffixOracle returns ECB_key(prefix || input || secret) with PKCS#7
// padding. prefix is nil for challenge 12 and random for challenge 14.
func newSuffixOracle(tb testing.TB, key, prefix, secret []byte) encryptFunc {
	return func(input []byte) []byte {
		pt := bytes.Join([][]byte{prefix, input, secret}, nil)
		pt, err := aesutil.PKCS7Pad(pt, aesutil.BlockSize)
		if err != nil {
			tb.Fatalf("pad: %v", err)
		}
		ct, err := aesutil.ECBEncrypt(key, pt)
		if err != nil {
			tb.Fatalf("encrypt: %v", err)
		}
		return ct
	}
}

// probeSizes finds the block size and the length of whatever the oracle adds
// around our input. With an empty input the ciphertext is L0 bytes. Adding n
// bytes, the length first jumps (by one block) when the plaintext exactly
// fills its blocks, which forces a full block of padding: then
// hidden + n == L0, so hidden = L0 - n.
func probeSizes(oracle encryptFunc) (blockSize, hiddenLen int, err error) {
	l0 := len(oracle(nil))
	for n := 1; n <= 256; n++ {
		if l := len(oracle(bytes.Repeat([]byte{'A'}, n))); l > l0 {
			return l - l0, l0 - n, nil
		}
	}
	return 0, 0, errors.New("ciphertext length never changed")
}

// byteAtATimeECB recovers the secret suffix appended by an ECB oracle of the
// form ECB(input || secret).
func byteAtATimeECB(oracle encryptFunc) ([]byte, error) {
	bs, secretLen, err := probeSizes(oracle)
	if err != nil {
		return nil, err
	}
	if !detectECB(oracle, bs) {
		return nil, errors.New("oracle is not using ECB")
	}

	known := make([]byte, 0, secretLen)
	for len(known) < secretLen {
		k := len(known)
		// Filler so that secret[k] is the last byte of block k/bs.
		filler := bytes.Repeat([]byte{'A'}, bs-1-k%bs)
		blk := k / bs
		target := oracle(filler)[blk*bs : (blk+1)*bs]

		// The bs-1 bytes preceding secret[k] are all known: filler + known.
		window := append(bytes.Clone(filler), known...)
		window = window[len(window)-(bs-1):]

		c, ok := matchLastByte(oracle, window, target)
		if !ok {
			return nil, fmt.Errorf("no dictionary match for byte %d", k)
		}
		known = append(known, c)
	}
	return known, nil
}

// matchLastByte tries all 256 values of the last byte after window and returns
// the one whose first ciphertext block equals target.
func matchLastByte(oracle encryptFunc, window, target []byte) (byte, bool) {
	probe := append(bytes.Clone(window), 0)
	for c := range 256 {
		probe[len(probe)-1] = byte(c)
		if bytes.Equal(oracle(probe)[:len(target)], target) {
			return byte(c), true
		}
	}
	return 0, false
}
