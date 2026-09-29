package set1_test

import (
	"encoding/hex"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// Challenge 5 — Implement repeating-key XOR.
// A byte-level Vigenère cipher. Its weakness (exploited in challenge 6): every
// len(key)-th byte is XORed with the same key byte.
func TestChallenge05(t *testing.T) {
	const (
		pt   = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
		want = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	)

	got, err := xorutil.RepeatingKey([]byte(pt), []byte("ICE"))
	if err != nil {
		t.Fatalf("RepeatingKey: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("RepeatingKey = %x\nwant           %s", got, want)
	}
}
