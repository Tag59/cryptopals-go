package set2_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/testutil"
)

// Challenge 10 — Implement CBC mode.
// CBC chains blocks: each plaintext block is XORed with the previous
// ciphertext block before encryption, so equal plaintext blocks no longer give
// equal ciphertext blocks. Built by hand in internal/aesutil/cbc.go on top of
// the raw AES block, and cross-checked there against crypto/cipher.
func TestChallenge10(t *testing.T) {
	ct := testutil.ReadBase64File(t, "testdata/10.txt")
	iv := make([]byte, aesutil.BlockSize) // all-zero IV, as in the statement

	padded, err := aesutil.CBCDecrypt([]byte("YELLOW SUBMARINE"), iv, ct)
	if err != nil {
		t.Fatalf("CBCDecrypt: %v", err)
	}
	pt, err := aesutil.PKCS7Unpad(padded, aesutil.BlockSize)
	if err != nil {
		t.Fatalf("PKCS7Unpad: %v", err)
	}
	// Same plaintext as challenges 6 and 7.
	testutil.AssertSHA256(t, pt, "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6")
}
