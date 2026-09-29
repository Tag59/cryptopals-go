package set4_test

import (
	"bytes"
	"crypto/subtle"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/mdhash"
)

// Challenge 30 — Break an MD4 keyed MAC using length extension.
//
// Same attack as challenge 29: MD4 is also Merkle–Damgård, its digest is its
// final state, and the glue padding only depends on the message length. The
// only differences are a 4-word state and little-endian encodings.
func TestChallenge30(t *testing.T) {
	mac := newPrefixMAC()
	msg := []byte(adminMessage)
	tag := mac.md4(msg)
	suffix := []byte(";admin=true")

	for keyLen := range 64 {
		glue := mdhash.MD4Padding(uint64(keyLen + len(msg)))
		forgedTag, err := mdhash.MD4Resume(tag, uint64(keyLen+len(msg)+len(glue)), suffix)
		if err != nil {
			t.Fatal(err)
		}
		forged := bytes.Join([][]byte{msg, glue, suffix}, nil)
		if mac.verifyMD4(forged, forgedTag) {
			if keyLen != len(mac.key) {
				t.Errorf("forgery accepted with key length %d, real one is %d", keyLen, len(mac.key))
			}
			return
		}
	}
	t.Fatal("no key length produced an accepted forgery")
}

func (m *prefixMAC) md4(msg []byte) [mdhash.MD4Size]byte {
	return mdhash.MD4(append(bytes.Clone(m.key), msg...))
}

func (m *prefixMAC) verifyMD4(msg []byte, tag [mdhash.MD4Size]byte) bool {
	want := m.md4(msg)
	return subtle.ConstantTimeCompare(want[:], tag[:]) == 1
}
