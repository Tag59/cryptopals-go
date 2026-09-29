package mdhash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"testing"
)

// Cross-check against crypto/hmac, with keys shorter than, equal to and
// longer than the block size (the latter are hashed first).
func TestHMACSHA1MatchesStdlib(t *testing.T) {
	for _, keyLen := range []int{0, 1, 20, BlockSize - 1, BlockSize, BlockSize + 1, 3 * BlockSize} {
		key, msg := make([]byte, keyLen), make([]byte, 100)
		rand.Read(key)
		rand.Read(msg)
		h := hmac.New(sha1.New, key)
		h.Write(msg)
		if got, want := HMACSHA1(key, msg), h.Sum(nil); string(got[:]) != string(want) {
			t.Errorf("key len %d: HMACSHA1 = %x, want %x", keyLen, got, want)
		}
	}
}
