package set3_test

import (
	"bytes"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/freq"
	"github.com/Tag59/cryptopals-go/internal/testutil"
	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// Challenge 20 — Break fixed-nonce CTR statistically.
//
// Same many-time pad as challenge 19, solved the systematic way: truncate
// every ciphertext to the shortest length L and concatenate them. The result
// is exactly a repeating-key XOR with a key of size L (the keystream prefix),
// so challenge 6's column-wise attack applies unchanged, with every column
// backed by all 60 samples.
//
// Column 0 is the weak spot: it holds line initials, whose distribution is
// not that of running English (here, a wrong key turning apostrophes into
// spaces wins on score). As in challenge 19, it is re-solved with the
// constraint that lines start with a capital letter (fixLeadingColumn).
func TestChallenge20(t *testing.T) {
	key := aesutil.RandomBytes(16)
	var pts, cts [][]byte
	for _, line := range testutil.ReadLines(t, "testdata/20.txt") {
		pt := testutil.MustBase64(t, line)
		ct, err := aesutil.CTR(key, 0, pt)
		if err != nil {
			t.Fatal(err)
		}
		pts, cts = append(pts, pt), append(cts, ct)
	}

	minLen := len(cts[0])
	for _, ct := range cts {
		minLen = min(minLen, len(ct))
	}
	var joined []byte
	for _, ct := range cts {
		joined = append(joined, ct[:minLen]...)
	}

	ks, err := freq.BreakRepeatingKeyXORWithSize(joined, minLen)
	if err != nil {
		t.Fatalf("BreakRepeatingKeyXORWithSize: %v", err)
	}
	fixLeadingColumn(ks, cts)

	for i, ct := range cts {
		got, err := xorutil.Fixed(ct[:minLen], ks)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pts[i][:minLen]) {
			t.Errorf("line %d: truncated plaintext does not match", i)
		}
	}
}
