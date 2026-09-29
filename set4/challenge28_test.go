package set4_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/subtle"
	"math/rand/v2"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/mdhash"
)

// Challenge 28 — Implement a SHA-1 keyed MAC.
//
// The naive "secret-prefix" MAC is SHA1(key || message). Without the key you
// cannot compute the MAC of an arbitrary message, and changing the message
// or the tag makes verification fail. It looks fine — challenge 29 shows it
// is not.
func TestChallenge28(t *testing.T) {
	mac := newPrefixMAC()
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	tag := mac.sha1(msg)

	if want := sha1.Sum(append(bytes.Clone(mac.key), msg...)); tag != want {
		t.Fatalf("MAC = %x, want SHA1(key||msg) = %x", tag, want)
	}
	if !mac.verifySHA1(msg, tag) {
		t.Fatal("legitimate message rejected")
	}

	tampered := bytes.Clone(msg)
	tampered[len(tampered)-1] ^= 1
	if mac.verifySHA1(tampered, tag) {
		t.Error("tampered message accepted")
	}
	badTag := tag
	badTag[0] ^= 1
	if mac.verifySHA1(msg, badTag) {
		t.Error("tampered tag accepted")
	}
	if forged := mdhash.SHA1(tampered); mac.verifySHA1(tampered, forged) {
		t.Error("keyless hash accepted as a MAC")
	}
}

// prefixMAC is the secret-prefix MAC H(key || message), with a key of
// unknown (random) length. Challenges 29 and 30 break it.
type prefixMAC struct{ key []byte }

func newPrefixMAC() *prefixMAC {
	return &prefixMAC{key: aesutil.RandomBytes(8 + rand.IntN(25))}
}

func (m *prefixMAC) sha1(msg []byte) [mdhash.SHA1Size]byte {
	return mdhash.SHA1(append(bytes.Clone(m.key), msg...))
}

func (m *prefixMAC) verifySHA1(msg []byte, tag [mdhash.SHA1Size]byte) bool {
	want := m.sha1(msg)
	return subtle.ConstantTimeCompare(want[:], tag[:]) == 1
}
