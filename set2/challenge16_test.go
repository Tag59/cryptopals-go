package set2_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 16 — CBC bitflipping attacks.
//
// The server wraps our userdata between fixed strings, escapes ';' and '=',
// and CBC-encrypts the result. It later grants admin rights if the decrypted
// string contains ";admin=true;". Escaping blocks direct injection, but CBC
// decryption computes P[i] = D(C[i]) ^ C[i-1]: XORing a value into C[i-1]
// XORs the same value into P[i]. Block i-1 is garbled in the process, but it
// only held our own userdata. Full write-up in docs/16-cbc-bitflipping.md.
//
// Lesson: CBC provides confidentiality, not integrity. Unauthenticated
// ciphertext is malleable; use an AEAD or encrypt-then-MAC.
func TestChallenge16(t *testing.T) {
	const bs = aesutil.BlockSize
	srv := newCommentServer()

	t.Run("escaping blocks naive injection", func(t *testing.T) {
		ct, err := srv.encrypt(";admin=true;")
		if err != nil {
			t.Fatal(err)
		}
		if admin, err := srv.isAdmin(ct); err != nil || admin {
			t.Fatalf("isAdmin = %v, %v; want false, nil", admin, err)
		}
	})

	t.Run("bit flipping", func(t *testing.T) {
		// The prefix is exactly two blocks, so our input starts at block 2.
		// Block 2 is the sacrificial block, block 3 the one we rewrite.
		known := strings.Repeat("A", bs)
		want := ";admin=true;AAAA"
		ct, err := srv.encrypt(known + known)
		if err != nil {
			t.Fatal(err)
		}

		forged := bytes.Clone(ct)
		for i := range bs {
			forged[2*bs+i] ^= known[i] ^ want[i]
		}

		admin, err := srv.isAdmin(forged)
		if err != nil {
			t.Fatalf("isAdmin: %v", err)
		}
		if !admin {
			t.Error("forged ciphertext was not accepted as admin")
		}
	})
}

const (
	commentPrefix = "comment1=cooking%20MCs;userdata="
	commentSuffix = ";comment2=%20like%20a%20pound%20of%20bacon"
)

// commentServer holds a secret key and a fixed IV (the IV choice does not
// matter for this attack).
type commentServer struct{ key, iv []byte }

func newCommentServer() *commentServer {
	return &commentServer{
		key: aesutil.RandomBytes(16),
		iv:  aesutil.RandomBytes(aesutil.BlockSize),
	}
}

var metaEscaper = strings.NewReplacer(";", "%3B", "=", "%3D")

func (s *commentServer) encrypt(userdata string) ([]byte, error) {
	pt := commentPrefix + metaEscaper.Replace(userdata) + commentSuffix
	padded, err := aesutil.PKCS7Pad([]byte(pt), aesutil.BlockSize)
	if err != nil {
		return nil, err
	}
	return aesutil.CBCEncrypt(s.key, s.iv, padded)
}

func (s *commentServer) isAdmin(ct []byte) (bool, error) {
	padded, err := aesutil.CBCDecrypt(s.key, s.iv, ct)
	if err != nil {
		return false, err
	}
	pt, err := aesutil.PKCS7Unpad(padded, aesutil.BlockSize)
	if err != nil {
		return false, err
	}
	return bytes.Contains(pt, []byte(";admin=true;")), nil
}
