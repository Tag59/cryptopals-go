package set4_test

import (
	"bytes"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/mdhash"
)

// Challenge 29 — Break a SHA-1 keyed MAC using length extension.
//
// SHA-1 is a Merkle–Damgård hash: its digest is its whole internal state after
// the last (padded) block. From MAC = SHA1(key || msg) we can therefore resume
// hashing and obtain, without the key,
//
//	SHA1(key || msg || glue || suffix)
//
// where glue is the padding SHA-1 appended to key || msg. It depends only on
// the length of key || msg, so we just try every plausible key length until
// the server accepts the forgery.
//
// Lesson: H(key || m) is not a MAC. Use HMAC, which hashes twice with the key
// on both sides precisely to defeat length extension.
func TestChallenge29(t *testing.T) {
	mac := newPrefixMAC()
	msg := []byte(adminMessage)
	tag := mac.sha1(msg)
	suffix := []byte(";admin=true")

	for keyLen := range 64 {
		forged, forgedTag, err := extendSHA1(msg, tag, keyLen, suffix)
		if err != nil {
			t.Fatal(err)
		}
		if mac.verifySHA1(forged, forgedTag) {
			if !bytes.HasSuffix(forged, suffix) || !bytes.HasPrefix(forged, msg) {
				t.Fatalf("forged message %q does not extend the original", forged)
			}
			if keyLen != len(mac.key) {
				t.Errorf("forgery accepted with key length %d, real one is %d", keyLen, len(mac.key))
			}
			return
		}
	}
	t.Fatal("no key length produced an accepted forgery")
}

const adminMessage = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

// extendSHA1 forges (msg || glue || suffix, tag') from (msg, tag) assuming a
// key of keyLen bytes.
func extendSHA1(msg []byte, tag [mdhash.SHA1Size]byte, keyLen int, suffix []byte) ([]byte, [mdhash.SHA1Size]byte, error) {
	glue := mdhash.SHA1Padding(uint64(keyLen + len(msg)))
	processed := uint64(keyLen + len(msg) + len(glue))
	forgedTag, err := mdhash.SHA1Resume(tag, processed, suffix)
	forged := bytes.Join([][]byte{msg, glue, suffix}, nil)
	return forged, forgedTag, err
}
