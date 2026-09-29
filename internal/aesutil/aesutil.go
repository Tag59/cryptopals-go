// Package aesutil builds AES block-cipher modes by hand on top of the raw
// block primitive from crypto/aes. It exists to study (and break) the modes;
// real code should use an AEAD such as crypto/cipher.NewGCM instead.
package aesutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// BlockSize is the AES block size in bytes.
const BlockSize = aes.BlockSize

// ErrNotBlockAligned is returned when a buffer's length is not a multiple of
// the block size. Modes here never pad implicitly: padding is an explicit,
// separate step, which is exactly where later challenges attack.
var ErrNotBlockAligned = errors.New("aesutil: input is not a multiple of the block size")

// RandomBytes returns n bytes from the OS CSPRNG. Even in attack demos, keys
// and IVs come from crypto/rand: the attacks must not rely on weak randomness.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) // never returns an error since Go 1.24
	return b
}

// newBlock wraps aes.NewCipher with a package-prefixed error.
func newBlock(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesutil: %w", err)
	}
	return block, nil
}

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

// RepeatedBlocks counts blocks of size blockSize that duplicate an earlier
// block in b. Under ECB, a repeated 16-byte plaintext block always yields a
// repeated ciphertext block; under a sound mode, a collision among random
// 128-bit blocks is astronomically unlikely. A non-zero count is therefore a
// strong ECB fingerprint.
func RepeatedBlocks(b []byte, blockSize int) (int, error) {
	if blockSize < 1 || len(b)%blockSize != 0 {
		return 0, fmt.Errorf("%w (%d bytes, block size %d)", ErrNotBlockAligned, len(b), blockSize)
	}
	seen := make(map[string]bool, len(b)/blockSize)
	dups := 0
	for i := 0; i < len(b); i += blockSize {
		blk := string(b[i : i+blockSize])
		if seen[blk] {
			dups++
		}
		seen[blk] = true
	}
	return dups, nil
}

func ecb(key, in []byte, encrypt bool) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
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
