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

func TestBreakManyTimePad(t *testing.T) {
	// Cut a continuous English text into equal-length lines: each column is
	// then a fair sample of English, about 30 bytes per column.
	text := "when a stream cipher reuses its keystream, every ciphertext leaks " +
		"information about every other one. the attacker does not need the key: " +
		"stacking the messages on top of each other turns each column into a " +
		"tiny puzzle with only two hundred and fifty six possible answers, and " +
		"the statistics of written english pick the right one almost every time. " +
		"this is why protocols insist that a nonce must never be used twice with " +
		"the same key, and why random nonces must be long enough that collisions " +
		"are out of reach. history is full of systems that forgot this simple rule " +
		"and paid for it, from wartime teleprinters to wireless network protocols."
	const width = 20
	ks := []byte("0123456789ABCDEFGHIJ")
	var cts [][]byte
	for i := 0; i+width <= len(text); i += width {
		ct, err := xorutil.Fixed([]byte(text[i:i+width]), ks)
		if err != nil {
			t.Fatal(err)
		}
		cts = append(cts, ct)
	}
	got, err := BreakManyTimePad(cts)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(ks) {
		t.Errorf("keystream = %q, want %q (%d lines)", got, ks, len(cts))
	}
	if _, err := BreakManyTimePad(nil); !errors.Is(err, ErrEmptyInput) {
		t.Errorf("empty input: got err %v, want ErrEmptyInput", err)
	}
}

func TestGuessKeySizesInvalidRange(t *testing.T) {
	for _, r := range [][2]int{{0, 5}, {5, 4}, {40, 50}} {
		if _, err := GuessKeySizes([]byte("short"), r[0], r[1]); !errors.Is(err, ErrKeySizeRange) {
			t.Errorf("range %v: got err %v, want ErrKeySizeRange", r, err)
		}
	}
}
