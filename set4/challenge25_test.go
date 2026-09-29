package set4_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/testutil"
)

// Challenge 25 — Break "random access read/write" AES CTR.
//
// CTR allows editing ciphertext in place: to change bytes at an offset, XOR
// the new plaintext with the keystream at that offset. The server exposes such
// an edit API. Editing with newtext = the ciphertext itself returns
// ct ^ KS = pt: the service decrypts for us.
//
// Lesson: a keystream must never encrypt two different plaintexts. Any API
// that re-encrypts attacker-chosen data at the same position (same key, nonce
// and counter) hands out the keystream.
func TestChallenge25(t *testing.T) {
	ecb := testutil.ReadBase64File(t, "testdata/25.txt")
	padded, err := aesutil.ECBDecrypt([]byte("YELLOW SUBMARINE"), ecb)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aesutil.PKCS7Unpad(padded, aesutil.BlockSize)
	if err != nil {
		t.Fatal(err)
	}

	srv := &editServer{key: aesutil.RandomBytes(16)}
	ct, err := aesutil.CTR(srv.key, 0, pt)
	if err != nil {
		t.Fatal(err)
	}

	got, err := srv.edit(ct, 0, ct)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("recovered plaintext does not match")
	}
}

// editServer holds the CTR key; the attacker only calls edit.
type editServer struct{ key []byte }

var errEditRange = errors.New("edit out of range")

// edit returns ct with the plaintext at [offset, offset+len(newText)) replaced
// by newText, re-encrypted under the same key and nonce.
func (s *editServer) edit(ct []byte, offset int, newText []byte) ([]byte, error) {
	if offset < 0 || offset+len(newText) > len(ct) {
		return nil, errEditRange
	}
	pt, err := aesutil.CTR(s.key, 0, ct)
	if err != nil {
		return nil, err
	}
	copy(pt[offset:], newText)
	return aesutil.CTR(s.key, 0, pt)
}
