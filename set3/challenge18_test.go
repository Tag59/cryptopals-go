package set3_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/testutil"
)

// Challenge 18 — Implement CTR, the stream cipher mode.
// CTR encrypts a counter and XORs the result with the data: a stream cipher
// built from a block cipher. No padding, random access, and encryption is its
// own inverse. Its one hard rule: never reuse a (key, nonce) pair.
func TestChallenge18(t *testing.T) {
	ct := testutil.MustBase64(t, "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

	pt, err := aesutil.CTR([]byte("YELLOW SUBMARINE"), 0, ct)
	if err != nil {
		t.Fatalf("CTR: %v", err)
	}
	testutil.AssertSHA256(t, pt, "0e15ad04b165a34e8fe2dea7f9dda0a128b03c86d913a1dc8fb34272e436a2bc")
}
