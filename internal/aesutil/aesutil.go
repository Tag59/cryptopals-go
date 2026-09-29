// Package aesutil builds AES block-cipher modes by hand on top of the raw
// block primitive from crypto/aes. It exists to study (and break) the modes;
// real code should use an AEAD such as crypto/cipher.NewGCM instead.
package aesutil

import (
	"crypto/aes"
	"errors"
	"fmt"
)

// BlockSize is the AES block size in bytes.
const BlockSize = aes.BlockSize

// ErrNotBlockAligned is returned when a buffer's length is not a multiple of
// the block size. Modes here never pad implicitly: padding is an explicit,
// separate step, which is exactly where later challenges attack.
var ErrNotBlockAligned = errors.New("aesutil: input is not a multiple of the block size")

// ECBEncrypt encrypts each 16-byte block independently with the same key.
// Identical plaintext blocks give identical ciphertext blocks: ECB leaks the
// structure of the plaintext and must never be used for real data.
func ECBEncrypt(key, pt []byte) ([]byte, error) {
	return ecb(key, pt, true)
}

// ECBDecrypt is the inverse of ECBEncrypt.
func ECBDecrypt(key, ct []byte) ([]byte, error) {
	return ecb(key, ct, false)
}

func ecb(key, in []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesutil: %w", err)
	}
	if len(in)%BlockSize != 0 {
		return nil, fmt.Errorf("%w (%d bytes)", ErrNotBlockAligned, len(in))
	}
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += BlockSize {
		if encrypt {
			block.Encrypt(out[i:i+BlockSize], in[i:i+BlockSize])
		} else {
			block.Decrypt(out[i:i+BlockSize], in[i:i+BlockSize])
		}
	}
	return out, nil
}
