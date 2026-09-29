package set3_test

import (
	"bytes"
	mrand "math/rand/v2"
	"testing"
	"time"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/mt19937"
)

// Challenge 24 — Create the MT19937 stream cipher and break it.
//
// The "cipher" XORs data with the low byte of successive MT19937 outputs,
// seeded with a 16-bit key. Two lessons:
//
//  1. Key recovery: a 16-bit key is 65,536 candidates. With a few bytes of
//     known plaintext (here the 14 'A's we appended), try every seed and keep
//     the one that reproduces them. No cleverness needed.
//  2. Token forgery: a "random" password-reset token drawn from MT19937
//     seeded with the current time can be recognised, and therefore
//     predicted, by re-generating the tokens for every recent timestamp.
func TestChallenge24(t *testing.T) {
	t.Run("recover 16-bit key", func(t *testing.T) {
		key := uint16(mrand.UintN(1 << 16))
		known := bytes.Repeat([]byte{'A'}, 14)
		pt := append(aesutil.RandomBytes(5+mrand.IntN(20)), known...)
		ct := mtStream(uint32(key), pt)

		got, ok := recoverMTStreamKey(ct, known)
		if !ok {
			t.Fatal("no 16-bit seed reproduces the known plaintext")
		}
		if got != key {
			t.Errorf("recovered key %d, want %d", got, key)
		}
	})

	t.Run("detect time-seeded token", func(t *testing.T) {
		now := time.Now().Unix()
		weak := mtStream(uint32(now-mrand.Int64N(300)), make([]byte, 16))
		strong := aesutil.RandomBytes(16)

		if !isTimeSeededToken(weak, now, 3600) {
			t.Error("time-seeded token not detected")
		}
		if isTimeSeededToken(strong, now, 3600) {
			t.Error("crypto/rand token wrongly flagged as time-seeded")
		}
	})
}

// mtStream XORs data with a keystream made of the low byte of each MT19937
// output. Encryption and decryption are the same operation.
func mtStream(seed uint32, data []byte) []byte {
	mt := mt19937.New(seed)
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ byte(mt.Uint32())
	}
	return out
}

// recoverMTStreamKey brute-forces the 16-bit seed using a known plaintext
// suffix.
func recoverMTStreamKey(ct, knownSuffix []byte) (uint16, bool) {
	tail := len(ct) - len(knownSuffix)
	for k := range 1 << 16 {
		if bytes.Equal(mtStream(uint32(k), ct)[tail:], knownSuffix) {
			return uint16(k), true
		}
	}
	return 0, false
}

// isTimeSeededToken reports whether token equals the MT19937 keystream (i.e.
// the encryption of zeros) for some seed in the last window seconds.
func isTimeSeededToken(token []byte, now, window int64) bool {
	zeros := make([]byte, len(token))
	for ts := now; ts >= now-window; ts-- {
		if bytes.Equal(mtStream(uint32(ts), zeros), token) {
			return true
		}
	}
	return false
}
