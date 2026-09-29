package freq

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/Tag59/cryptopals-go/internal/xorutil"
)

// ErrKeySizeRange is returned for an invalid or unusable key-size range.
var ErrKeySizeRange = errors.New("freq: invalid key size range")

// KeySizeCandidate is a key length together with its normalised edit distance
// (lower means more likely).
type KeySizeCandidate struct {
	Size     int
	Distance float64
}

// GuessKeySizes ranks key sizes in [minSize, maxSize] for a repeating-key XOR
// ciphertext, most likely first.
//
// Why the Hamming distance reveals the key size: split ct into blocks of the
// guessed size k. If k is the real key length, two blocks were XORed with the
// same key bytes, so blockA ^ blockB = ptA ^ ptB: the key cancels out. Two
// English bytes differ by ~2-3 bits on average (ASCII letters share their high
// bits), whereas two random bytes differ by 4. With a wrong k the key does not
// cancel and the XOR looks random. Hence the true k minimises the Hamming
// distance, normalised by k so that different sizes compare fairly.
//
// Averaging over all consecutive block pairs, rather than only the first two
// as in the statement, makes the estimate far more stable.
func GuessKeySizes(ct []byte, minSize, maxSize int) ([]KeySizeCandidate, error) {
	if minSize < 1 || maxSize < minSize {
		return nil, fmt.Errorf("%w: [%d, %d]", ErrKeySizeRange, minSize, maxSize)
	}
	var out []KeySizeCandidate
	for k := minSize; k <= maxSize; k++ {
		blocks := len(ct) / k
		if blocks < 2 {
			break // not enough ciphertext to compare two blocks of this size
		}
		var total float64
		for i := 0; i+1 < blocks; i++ {
			d, err := xorutil.HammingDistance(ct[i*k:(i+1)*k], ct[(i+1)*k:(i+2)*k])
			if err != nil {
				return nil, err
			}
			total += float64(d) / float64(k)
		}
		out = append(out, KeySizeCandidate{Size: k, Distance: total / float64(blocks-1)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: ciphertext too short (%d bytes)", ErrKeySizeRange, len(ct))
	}
	slices.SortFunc(out, func(a, b KeySizeCandidate) int { return cmp.Compare(a.Distance, b.Distance) })
	return out, nil
}

// Transpose splits b into size columns: column j holds every byte whose index
// i satisfies i mod size == j. For a repeating-key XOR, each column was
// encrypted with a single key byte, turning one hard problem into size easy
// ones.
func Transpose(b []byte, size int) [][]byte {
	cols := make([][]byte, size)
	for i, c := range b {
		cols[i%size] = append(cols[i%size], c)
	}
	return cols
}

// BreakRepeatingKeyXORWithSize recovers a key of known length by transposing
// the ciphertext and breaking each column as a single-byte XOR.
func BreakRepeatingKeyXORWithSize(ct []byte, size int) ([]byte, error) {
	if size < 1 || size > len(ct) {
		return nil, fmt.Errorf("%w: size %d for %d bytes", ErrKeySizeRange, size, len(ct))
	}
	key := make([]byte, size)
	for j, col := range Transpose(ct, size) {
		r, err := BreakSingleByteXOR(col)
		if err != nil {
			return nil, fmt.Errorf("column %d: %w", j, err)
		}
		key[j] = r.Key
	}
	return key, nil
}

// RepeatingKeyResult is the outcome of BreakRepeatingKeyXOR.
type RepeatingKeyResult struct {
	Key       []byte
	Plaintext []byte
	Score     float64
}

// BreakRepeatingKeyXOR breaks a repeating-key XOR ciphertext without knowing
// the key: rank key sizes by normalised Hamming distance, fully solve the
// `tries` best candidates, and keep the plaintext that scores best as English.
// The distance heuristic is noisy; the final English score is not.
func BreakRepeatingKeyXOR(ct []byte, minSize, maxSize, tries int) (RepeatingKeyResult, error) {
	cands, err := GuessKeySizes(ct, minSize, maxSize)
	if err != nil {
		return RepeatingKeyResult{}, err
	}
	var best RepeatingKeyResult
	for i, c := range cands[:min(max(tries, 1), len(cands))] {
		key, err := BreakRepeatingKeyXORWithSize(ct, c.Size)
		if err != nil {
			return RepeatingKeyResult{}, err
		}
		pt, err := xorutil.RepeatingKey(ct, key)
		if err != nil {
			return RepeatingKeyResult{}, err
		}
		if s := Score(pt); i == 0 || s > best.Score {
			best = RepeatingKeyResult{Key: key, Plaintext: pt, Score: s}
		}
	}
	// A multiple of the true key size also scores well and yields the very
	// same plaintext (e.g. "secretsecret" for "secret"), so reduce the key to
	// its smallest period.
	best.Key = best.Key[:minimalPeriod(best.Key)]
	return best, nil
}

// minimalPeriod returns the smallest p such that key is key[:p] repeated.
func minimalPeriod(key []byte) int {
	for p := 1; p < len(key); p++ {
		if len(key)%p != 0 {
			continue
		}
		periodic := true
		for i := p; i < len(key) && periodic; i++ {
			periodic = key[i] == key[i-p]
		}
		if periodic {
			return p
		}
	}
	return len(key)
}
