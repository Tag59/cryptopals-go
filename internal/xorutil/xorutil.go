// Package xorutil provides the XOR primitives and encoding helpers shared by
// the challenges. It is intentionally low-level and not meant for production.
package xorutil

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// HexToBase64 decodes a hex string and re-encodes the raw bytes as standard
// base64. Cryptopals rule: always operate on raw bytes, never on encoded
// strings — encodings are only for display and transport.
func HexToBase64(s string) (string, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ErrLengthMismatch is returned when two buffers that must be XORed
// byte-for-byte do not have the same length.
var ErrLengthMismatch = errors.New("xorutil: buffers have different lengths")

// Fixed XORs two equal-length buffers. Unequal lengths are an error rather
// than a silent truncation: truncation hides bugs in attack code.
func Fixed(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("%w (%d vs %d)", ErrLengthMismatch, len(a), len(b))
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out, nil
}

// SingleByte XORs every byte of b with the key byte k.
func SingleByte(b []byte, k byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ k
	}
	return out
}

// ErrEmptyKey is returned when a repeating-key XOR is given no key.
var ErrEmptyKey = errors.New("xorutil: empty key")

// RepeatingKey XORs b with key repeated cyclically (Vigenère over bytes):
// out[i] = b[i] ^ key[i mod len(key)]. Encryption and decryption are the same.
func RepeatingKey(b, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ key[i%len(key)]
	}
	return out, nil
}

// HammingDistance counts the differing bits between two equal-length buffers,
// i.e. the population count of a ^ b.
func HammingDistance(a, b []byte) (int, error) {
	x, err := Fixed(a, b)
	if err != nil {
		return 0, err
	}
	d := 0
	for _, c := range x {
		d += bits.OnesCount8(c)
	}
	return d, nil
}
