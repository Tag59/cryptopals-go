package aesutil

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

// Cross-check the hand-written CBC against the standard library.
func TestCBCMatchesStdlib(t *testing.T) {
	key, iv := make([]byte, 16), make([]byte, BlockSize)
	pt := make([]byte, 5*BlockSize)
	for _, b := range [][]byte{key, iv, pt} {
		rand.Read(b)
	}

	got, err := CBCEncrypt(key, iv, pt)
	if err != nil {
		t.Fatal(err)
	}
	block, err := newBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, pt)
	if !bytes.Equal(got, want) {
		t.Fatalf("CBCEncrypt differs from crypto/cipher")
	}

	back, err := CBCDecrypt(key, iv, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, pt) {
		t.Errorf("CBCDecrypt round trip mismatch")
	}
}

func TestCBCErrors(t *testing.T) {
	key := make([]byte, 16)
	if _, err := CBCEncrypt(key, make([]byte, 8), make([]byte, 16)); !errors.Is(err, ErrInvalidIV) {
		t.Errorf("short IV: got err %v, want ErrInvalidIV", err)
	}
	if _, err := CBCDecrypt(key, make([]byte, 16), make([]byte, 17)); !errors.Is(err, ErrNotBlockAligned) {
		t.Errorf("unaligned: got err %v, want ErrNotBlockAligned", err)
	}
}
