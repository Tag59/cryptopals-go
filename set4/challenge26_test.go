package set4_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 26 — CTR bitflipping.
//
// Same scenario as challenge 16, with CTR instead of CBC. It is even easier:
// in CTR, C[i] = P[i] ^ KS[i], so flipping a ciphertext bit flips exactly the
// same plaintext bit and nothing else, with no garbled block. Knowing the
// plaintext at some position (our own input) is enough to write anything
// there: C'[i] = C[i] ^ P[i] ^ P'[i].
//
// Lesson: stream ciphers are maximally malleable. Confidentiality without
// integrity lets an attacker edit messages byte by byte.
func TestChallenge26(t *testing.T) {
	srv := &ctrCommentServer{key: aesutil.RandomBytes(16), nonce: 0x1122334455667788}

	known := strings.Repeat("A", 12)
	want := ";admin=true;"
	ct, err := srv.encrypt(known)
	if err != nil {
		t.Fatal(err)
	}
	if admin, err := srv.isAdmin(ct); err != nil || admin {
		t.Fatalf("before forgery: isAdmin = %v, %v; want false, nil", admin, err)
	}

	forged := bytes.Clone(ct)
	off := len(commentPrefix)
	for i := range known {
		forged[off+i] ^= known[i] ^ want[i]
	}

	admin, err := srv.isAdmin(forged)
	if err != nil {
		t.Fatalf("isAdmin: %v", err)
	}
	if !admin {
		t.Error("forged ciphertext was not accepted as admin")
	}
}

const (
	commentPrefix = "comment1=cooking%20MCs;userdata="
	commentSuffix = ";comment2=%20like%20a%20pound%20of%20bacon"
)

var metaEscaper = strings.NewReplacer(";", "%3B", "=", "%3D")

// ctrCommentServer is challenge 16's server, with CTR instead of CBC.
type ctrCommentServer struct {
	key   []byte
	nonce uint64
}

func (s *ctrCommentServer) encrypt(userdata string) ([]byte, error) {
	pt := commentPrefix + metaEscaper.Replace(userdata) + commentSuffix
	return aesutil.CTR(s.key, s.nonce, []byte(pt))
}

func (s *ctrCommentServer) isAdmin(ct []byte) (bool, error) {
	pt, err := aesutil.CTR(s.key, s.nonce, ct)
	if err != nil {
		return false, err
	}
	return bytes.Contains(pt, []byte(";admin=true;")), nil
}
