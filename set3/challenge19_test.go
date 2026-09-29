package set3_test

import (
	"bytes"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/freq"
	"github.com/Tag59/cryptopals-go/internal/testutil"
	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// Challenge 19 — Break fixed-nonce CTR mode using substitutions.
//
// Forty lines are CTR-encrypted under the same key AND the same nonce, so
// they all share one keystream: C_i = P_i ^ KS. That is a many-time pad.
//
//  1. Statistics: byte j of every ciphertext was XORed with the same KS[j], so
//     each column is a single-byte XOR (freq.BreakManyTimePad). This recovers
//     every column where enough lines are long enough.
//  2. Substitutions, where statistics cannot decide:
//     - Column 0 holds only letters, and XOR 0x20 merely swaps their case, so
//     "I have..." and "i have..." score identically. Knowing that verse lines
//     start with a capital settles it (fixLeadingColumn).
//     - The last columns are covered by only one to three lines. Reading the
//     partial decryption, the longest line ends in a garbled but guessable
//     phrase ("...changed in hi? ..."). Guessing that plaintext (a "crib")
//     gives KS = C ^ P_guess for those columns, which fixes the tail of every
//     other line at once; all lines becoming readable confirms the guess.
//
// Lesson: a nonce is not optional. One reuse turns CTR into a Vigenère
// cipher with a key as long as the message.
func TestChallenge19(t *testing.T) {
	key := aesutil.RandomBytes(16)
	var pts, cts [][]byte
	for _, line := range testutil.ReadLines(t, "testdata/19.txt") {
		pt := testutil.MustBase64(t, line)
		ct, err := aesutil.CTR(key, 0, pt) // same nonce for every line: the bug
		if err != nil {
			t.Fatal(err)
		}
		pts, cts = append(pts, pt), append(cts, ct)
	}

	ks, err := freq.BreakManyTimePad(cts)
	if err != nil {
		t.Fatalf("BreakManyTimePad: %v", err)
	}
	t.Logf("statistics alone: %d/%d lines fully correct", countCorrect(cts, pts, ks), len(pts))

	fixLeadingColumn(ks, cts)
	longest := 0
	for i, ct := range cts {
		if len(ct) > len(cts[longest]) {
			longest = i
		}
	}
	applyCrib(ks, cts[longest], []byte("his turn,"))

	if n := countCorrect(cts, pts, ks); n != len(pts) {
		t.Errorf("after crib: %d/%d lines fully correct", n, len(pts))
	}
}

// fixLeadingColumn re-solves column 0 with a constraint instead of letter
// frequencies: lines of verse start with a capital letter, so pick the key
// byte that makes the most lines do so. Column 0 is where frequency scoring
// is weakest: it holds line initials, whose distribution is not that of
// running English, and XOR 0x20 merely swaps the case of letters.
func fixLeadingColumn(ks []byte, cts [][]byte) {
	best, bestCount := ks[0], -1
	for k := range 256 {
		count := 0
		for _, ct := range cts {
			if c := ct[0] ^ byte(k); c >= 'A' && c <= 'Z' {
				count++
			}
		}
		if count > bestCount {
			best, bestCount = byte(k), count
		}
	}
	ks[0] = best
}

// applyCrib aligns a guessed plaintext with the end of ct and derives the
// keystream bytes it implies: KS[j] = C[j] ^ guess[j].
func applyCrib(ks, ct, guess []byte) {
	off := len(ct) - len(guess)
	for k, g := range guess {
		ks[off+k] = ct[off+k] ^ g
	}
}

// countCorrect counts the ciphertexts that decrypt exactly to their plaintext
// under keystream ks.
func countCorrect(cts, pts [][]byte, ks []byte) int {
	n := 0
	for i, ct := range cts {
		if got, err := xorutil.Fixed(ct, ks[:len(ct)]); err == nil && bytes.Equal(got, pts[i]) {
			n++
		}
	}
	return n
}
