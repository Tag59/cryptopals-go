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

func TestBreakRepeatingKeyXORRoundTrip(t *testing.T) {
	pt := []byte("It was the best of times, it was the worst of times, it was the age " +
		"of wisdom, it was the age of foolishness, it was the epoch of belief, it " +
		"was the epoch of incredulity, it was the season of light, it was the " +
		"season of darkness, it was the spring of hope, it was the winter of despair.")
	key := []byte("secret")
	ct, err := xorutil.RepeatingKey(pt, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BreakRepeatingKeyXOR(ct, 2, 20, 3)
	if err != nil {
		t.Fatalf("BreakRepeatingKeyXOR: %v", err)
	}
	if string(got.Key) != string(key) {
		t.Errorf("key = %q, want %q", got.Key, key)
	}
}

func TestGuessKeySizesInvalidRange(t *testing.T) {
	for _, r := range [][2]int{{0, 5}, {5, 4}, {40, 50}} {
		if _, err := GuessKeySizes([]byte("short"), r[0], r[1]); !errors.Is(err, ErrKeySizeRange) {
			t.Errorf("range %v: got err %v, want ErrKeySizeRange", r, err)
		}
	}
}
