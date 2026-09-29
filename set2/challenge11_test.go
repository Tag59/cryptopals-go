package set2_test

import (
	"bytes"
	mrand "math/rand/v2"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// encryptFunc is a black-box encryption oracle as seen by the attacker.
type encryptFunc func(pt []byte) []byte

// Challenge 11 — An ECB/CBC detection oracle.
//
// The oracle wraps our input with 5-10 random bytes on each side and flips a
// coin between ECB and CBC under a random key. The attacker controls the input,
// so it sends 3 blocks of identical bytes: whatever the prefix length (<16),
// at least two full aligned blocks consist only of that byte. Under ECB they
// encrypt identically; under CBC they do not. One chosen query is enough.
//
// Lesson: ECB leaks equality even under a random key, and a chosen-plaintext
// capability turns that leak into a mode fingerprint.
func TestChallenge11(t *testing.T) {
	const trials = 200
	for i := range trials {
		oracle, usedECB := newModeOracle(t)
		if got := detectECB(oracle, aesutil.BlockSize); got != usedECB {
			t.Fatalf("trial %d: detected ECB=%v, oracle used ECB=%v", i, got, usedECB)
		}
	}
}

// detectECB reports whether oracle encrypts in ECB mode, by looking for
// repeated ciphertext blocks after sending three blocks of identical bytes.
func detectECB(oracle encryptFunc, blockSize int) bool {
	ct := oracle(bytes.Repeat([]byte{'A'}, 3*blockSize))
	for i := 0; i+2*blockSize <= len(ct); i += blockSize {
		if bytes.Equal(ct[i:i+blockSize], ct[i+blockSize:i+2*blockSize]) {
			return true
		}
	}
	return false
}

// newModeOracle returns the oracle from the statement and, for verification
// only, the mode it secretly picked. Key and IV come from crypto/rand; the
// non-secret choices (mode, pad lengths) use math/rand/v2.
func newModeOracle(tb testing.TB) (encryptFunc, bool) {
	key := aesutil.RandomBytes(16)
	useECB := mrand.IntN(2) == 0
	return func(input []byte) []byte {
		pt := append(aesutil.RandomBytes(5+mrand.IntN(6)), input...)
		pt = append(pt, aesutil.RandomBytes(5+mrand.IntN(6))...)
		pt, err := aesutil.PKCS7Pad(pt, aesutil.BlockSize)
		if err != nil {
			tb.Fatalf("pad: %v", err)
		}
		var ct []byte
		if useECB {
			ct, err = aesutil.ECBEncrypt(key, pt)
		} else {
			ct, err = aesutil.CBCEncrypt(key, aesutil.RandomBytes(aesutil.BlockSize), pt)
		}
		if err != nil {
			tb.Fatalf("encrypt: %v", err)
		}
		return ct
	}, useECB
}
