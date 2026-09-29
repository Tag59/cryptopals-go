package set1_test

import (
	"testing"

	"github.com/Tag59/cryptopals-go/internal/freq"
	"github.com/Tag59/cryptopals-go/internal/testutil"
	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// Challenge 6 — Break repeating-key XOR.
//
// The attack, in three steps (details in internal/freq/repeating.go):
//
//  1. Key size: for each candidate k, measure the Hamming distance between
//     consecutive k-byte blocks, normalised by k. With the right k the key
//     cancels out (c1 ^ c2 = p1 ^ p2), and English bytes differ in fewer bits
//     than random ones, so the right k gives the smallest distance.
//  2. Transposition: gather every k-th byte into k columns. Each column was
//     XORed with one single key byte.
//  3. Solve each column as in challenge 3 (frequency analysis), concatenate
//     the k key bytes, decrypt.
//
// Lesson: reusing key material turns one long key into many tiny ones.
func TestChallenge06(t *testing.T) {
	t.Run("hamming", func(t *testing.T) {
		d, err := xorutil.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
		if err != nil {
			t.Fatal(err)
		}
		if d != 37 {
			t.Errorf("HammingDistance = %d, want 37", d)
		}
	})

	t.Run("break", func(t *testing.T) {
		ct := testutil.ReadBase64File(t, "testdata/6.txt")

		got, err := freq.BreakRepeatingKeyXOR(ct, 2, 40, 3)
		if err != nil {
			t.Fatalf("BreakRepeatingKeyXOR: %v", err)
		}
		if len(got.Key) != 29 {
			t.Errorf("key size = %d, want 29", len(got.Key))
		}
		testutil.AssertSHA256(t, got.Key, "2f5170c05bb11ae64396407fde94fa5437a4cd8f1e94516d55355c5faf418622")
		testutil.AssertSHA256(t, got.Plaintext, "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6")
	})
}
