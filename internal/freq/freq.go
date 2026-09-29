// Package freq implements English frequency analysis and uses it to break
// XOR-based ciphers whose keyspace per position is a single byte.
package freq

import (
	"errors"

	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// letterWeights holds approximate relative frequencies (%) of letters in
// English text. Space is the single most common character in prose, so it gets
// the highest weight: that alone discriminates most wrong keys.
var letterWeights = map[byte]float64{
	' ': 15.0,
	'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
	'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4,
	'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 0.98,
	'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.095, 'z': 0.074,
}

// nonPrintablePenalty is subtracted for bytes that essentially never appear in
// English text (control characters, non-ASCII). A wrong key produces many of
// them, so a strong penalty makes the right key stand out sharply.
const nonPrintablePenalty = 20.0

// byteScores is a 256-entry lookup table built once from letterWeights.
var byteScores = func() (s [256]float64) {
	for c := range 256 {
		b := byte(c)
		switch {
		case b == '\n' || b == '\r' || b == '\t':
			// neutral whitespace
		case b < 0x20 || b > 0x7e:
			s[c] = -nonPrintablePenalty
		}
	}
	for c, w := range letterWeights {
		s[c] = w
		if c >= 'a' && c <= 'z' {
			s[c-'a'+'A'] = w
		}
	}
	return s
}()

// Score rates how much b looks like English text: the higher, the better.
// It is normalised by length so that buffers of different sizes compare fairly.
func Score(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var total float64
	for _, c := range b {
		total += byteScores[c]
	}
	return total / float64(len(b))
}

// ErrEmptyInput is returned when there is nothing to analyse.
var ErrEmptyInput = errors.New("freq: empty input")

// SingleByteResult is the best candidate found by BreakSingleByteXOR.
type SingleByteResult struct {
	Key       byte
	Plaintext []byte
	Score     float64
}

// BreakSingleByteXOR brute-forces the 256 possible keys and keeps the one whose
// decryption scores best as English. The keyspace is tiny, so exhaustive search
// plus a good scoring function is all it takes.
func BreakSingleByteXOR(ct []byte) (SingleByteResult, error) {
	if len(ct) == 0 {
		return SingleByteResult{}, ErrEmptyInput
	}
	var best SingleByteResult
	for k := range 256 {
		pt := xorutil.SingleByte(ct, byte(k))
		if s := Score(pt); k == 0 || s > best.Score {
			best = SingleByteResult{Key: byte(k), Plaintext: pt, Score: s}
		}
	}
	return best, nil
}
