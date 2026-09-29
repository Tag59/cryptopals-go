package set4_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 27 — Recover the key from CBC with IV = Key.
//
// Reusing the key as IV "saves" transmitting an IV. When the receiver rejects
// a message containing non-ASCII bytes, its error echoes the decrypted
// plaintext. Send C1 || 0 || C1 (plus the last two original blocks, so the
// padding stays valid). Then:
//
//	P'1 = D(C1) ^ IV = D(C1) ^ K
//	P'3 = D(C1) ^ 0  = D(C1)
//
// so P'1 ^ P'3 = K. One query and a verbose error reveal the key itself.
//
// Lesson: the IV must be unpredictable and independent of the key, and error
// messages must never echo decrypted data.
func TestChallenge27(t *testing.T) {
	const bs = aesutil.BlockSize
	srv := &ivKeyServer{key: aesutil.RandomBytes(16)}

	ct, err := srv.encrypt([]byte("userdata=a perfectly ordinary message of four blocks!!"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) < 3*bs {
		t.Fatalf("ciphertext too short: %d bytes, need at least 3 blocks", len(ct))
	}
	if err := srv.receive(ct); err != nil {
		t.Fatalf("legitimate message rejected: %v", err)
	}

	c1 := ct[:bs]
	forged := bytes.Join([][]byte{c1, make([]byte, bs), c1, ct[len(ct)-2*bs:]}, nil)

	var asciiErr *nonASCIIError
	if err := srv.receive(forged); !errors.As(err, &asciiErr) {
		t.Fatalf("receive(forged) = %v, want a *nonASCIIError", err)
	}
	p := asciiErr.plaintext
	key := make([]byte, bs)
	for i := range key {
		key[i] = p[i] ^ p[2*bs+i]
	}

	if !bytes.Equal(key, srv.key) {
		t.Fatalf("recovered key %x, want %x", key, srv.key)
	}
}

// nonASCIIError is the receiver's overly helpful error: it carries the whole
// decrypted plaintext.
type nonASCIIError struct{ plaintext []byte }

func (e *nonASCIIError) Error() string {
	return fmt.Sprintf("invalid message, non-ASCII plaintext: %q", e.plaintext)
}

// ivKeyServer encrypts and decrypts in CBC mode using the key as IV.
type ivKeyServer struct{ key []byte }

func (s *ivKeyServer) encrypt(pt []byte) ([]byte, error) {
	padded, err := aesutil.PKCS7Pad(pt, aesutil.BlockSize)
	if err != nil {
		return nil, err
	}
	return aesutil.CBCEncrypt(s.key, s.key, padded)
}

// receive decrypts ct and rejects it if the plaintext contains a byte >= 0x80.
func (s *ivKeyServer) receive(ct []byte) error {
	pt, err := aesutil.CBCDecrypt(s.key, s.key, ct)
	if err != nil {
		return err
	}
	for _, c := range pt {
		if c >= 0x80 {
			return &nonASCIIError{plaintext: pt}
		}
	}
	_, err = aesutil.PKCS7Unpad(pt, aesutil.BlockSize)
	return err
}
