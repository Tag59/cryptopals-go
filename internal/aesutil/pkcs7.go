package aesutil

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrInvalidPadding is returned by PKCS7Unpad for malformed padding.
var ErrInvalidPadding = errors.New("aesutil: invalid PKCS#7 padding")

// PKCS7Pad appends n bytes of value n so that the result is a multiple of
// blockSize, with 1 <= n <= blockSize. A full block of padding is added when
// the input is already aligned, so that unpadding is always unambiguous.
func PKCS7Pad(b []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("aesutil: PKCS#7 block size %d out of range [1, 255]", blockSize)
	}
	n := blockSize - len(b)%blockSize
	out := make([]byte, len(b), len(b)+n)
	copy(out, b)
	return append(out, bytes.Repeat([]byte{byte(n)}, n)...), nil
}

// PKCS7Unpad validates and strips PKCS#7 padding. Validation is strict: every
// padding byte is checked. Beware that the error it returns, if observable by
// an attacker, is precisely the oracle exploited in the CBC padding oracle
// attack (challenge 17).
func PKCS7Unpad(b []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("aesutil: PKCS#7 block size %d out of range [1, 255]", blockSize)
	}
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize {
		return nil, ErrInvalidPadding
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, ErrInvalidPadding
		}
	}
	return b[:len(b)-n], nil
}
