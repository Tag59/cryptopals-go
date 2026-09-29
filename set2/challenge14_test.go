package set2_test

import (
	"bytes"
	"errors"
	mrand "math/rand/v2"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/testutil"
)

// Challenge 14 — Byte-at-a-time ECB decryption (Harder).
//
// Now the oracle computes ECB(random-prefix || input || secret), with a
// prefix of fixed but unknown length. We reduce it to challenge 12:
//
//  1. Find the prefix length: send j filler bytes followed by two blocks of
//     filler, for j = 0..bs-1. The first j that yields two identical adjacent
//     ciphertext blocks at index i means the prefix plus j bytes ends on a
//     block boundary: prefixLen = i*bs - j.
//     Pitfall: if the prefix happens to end with the filler byte, the boundary
//     is detected one step early and the result is too large. Running the
//     probe with two different filler bytes and keeping the minimum removes
//     that edge case (the prefix cannot end with both).
//  2. Wrap the oracle: pad our input to realign it on a block boundary and
//     drop the prefix blocks from the output. The wrapped oracle behaves
//     exactly like ECB(input || secret), so byteAtATimeECB applies unchanged.
func TestChallenge14(t *testing.T) {
	secret := testutil.ReadBase64File(t, "testdata/12.txt")

	endsWith := func(b byte, n int) []byte { return append(aesutil.RandomBytes(n-1), b) }
	prefixes := map[string][]byte{
		"empty":              nil,
		"one block":          aesutil.RandomBytes(aesutil.BlockSize),
		"ends with filler A": endsWith('A', 21),
		"ends with filler B": endsWith('B', 37),
	}
	for i := range 8 {
		prefixes["random "+string(rune('0'+i))] = aesutil.RandomBytes(1 + mrand.IntN(64))
	}

	for name, prefix := range prefixes {
		t.Run(name, func(t *testing.T) {
			oracle := newSuffixOracle(t, aesutil.RandomBytes(16), prefix, secret)

			n, err := findPrefixLen(oracle, aesutil.BlockSize)
			if err != nil {
				t.Fatalf("findPrefixLen: %v", err)
			}
			if n != len(prefix) {
				t.Fatalf("prefix length = %d, want %d", n, len(prefix))
			}
			got, err := byteAtATimeECB(stripPrefix(oracle, n, aesutil.BlockSize))
			if err != nil {
				t.Fatalf("byteAtATimeECB: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Errorf("recovered secret does not match")
			}
		})
	}
}

// findPrefixLen measures the length of the unknown prefix an ECB oracle puts
// before our input.
func findPrefixLen(oracle encryptFunc, bs int) (int, error) {
	best := -1
	for _, filler := range []byte{'A', 'B'} {
		n, err := prefixLenWith(oracle, bs, filler)
		if err != nil {
			return 0, err
		}
		if best < 0 || n < best {
			best = n
		}
	}
	return best, nil
}

func prefixLenWith(oracle encryptFunc, bs int, filler byte) (int, error) {
	for j := range bs {
		ct := oracle(bytes.Repeat([]byte{filler}, j+2*bs))
		for i := 0; i+2*bs <= len(ct); i += bs {
			if bytes.Equal(ct[i:i+bs], ct[i+bs:i+2*bs]) {
				return i - j, nil
			}
		}
	}
	return 0, errors.New("no aligned pair of identical blocks found")
}

// stripPrefix turns ECB(prefix || input || secret) into ECB(input || secret)
// by realigning the input and cutting off the prefix blocks.
func stripPrefix(oracle encryptFunc, prefixLen, bs int) encryptFunc {
	pad := (bs - prefixLen%bs) % bs
	skip := prefixLen + pad
	return func(input []byte) []byte {
		ct := oracle(append(bytes.Repeat([]byte{'X'}, pad), input...))
		return ct[skip:]
	}
}
