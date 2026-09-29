package set1_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 7 — AES in ECB mode.
// No attack yet: we build ECB by hand from the raw AES block function to
// understand what a "mode" is. ECB = apply the block cipher to each block
// independently, which is precisely its flaw (see challenge 8).
func TestChallenge07(t *testing.T) {
	ct := readBase64File(t, "testdata/7.txt")

	padded, err := aesutil.ECBDecrypt([]byte("YELLOW SUBMARINE"), ct)
	if err != nil {
		t.Fatalf("ECBDecrypt: %v", err)
	}
	pt, err := aesutil.PKCS7Unpad(padded, aesutil.BlockSize)
	if err != nil {
		t.Fatalf("PKCS7Unpad: %v", err)
	}
	// Same plaintext as challenge 6: both tests pin the same digest.
	assertSHA256(t, pt, "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6")
}
