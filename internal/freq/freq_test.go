package freq

import (
	"errors"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

func TestScorePrefersEnglish(t *testing.T) {
	english := []byte("the quick brown fox jumps over the lazy dog")
	garbage := []byte{0x01, 0x9f, 0xff, 0x13, 0x00, 0x7f, 0x80, 0x02}
	if Score(english) <= Score(garbage) {
		t.Errorf("Score(english)=%.2f <= Score(garbage)=%.2f", Score(english), Score(garbage))
	}
}

func TestBreakSingleByteXORRoundTrip(t *testing.T) {
	pt := []byte("Frequency analysis breaks any single-byte XOR in a heartbeat.")
	const key = 0x5a
	got, err := BreakSingleByteXOR(xorutil.SingleByte(pt, key))
	if err != nil {
		t.Fatalf("BreakSingleByteXOR: %v", err)
	}
	if got.Key != key || string(got.Plaintext) != string(pt) {
		t.Errorf("got key %#x plaintext %q, want %#x %q", got.Key, got.Plaintext, key, pt)
	}
}

func TestBreakSingleByteXOREmpty(t *testing.T) {
	if _, err := BreakSingleByteXOR(nil); !errors.Is(err, ErrEmptyInput) {
		t.Errorf("got err %v, want ErrEmptyInput", err)
	}
}
