package set1_test

import (
	"encoding/hex"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// Challenge 2 — Fixed XOR.
// XOR is its own inverse (a ^ b ^ b = a): the building block of every stream
// cipher and of most attacks in the following challenges.
func TestChallenge02(t *testing.T) {
	a := mustHex(t, "1c0111001f010100061a024b53535009181c")
	b := mustHex(t, "686974207468652062756c6c277320657965")
	const want = "746865206b696420646f6e277420706c6179"

	got, err := xorutil.Fixed(a, b)
	if err != nil {
		t.Fatalf("Fixed: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("Fixed = %x, want %s", got, want)
	}
}
