package aesutil

import (
	"crypto/subtle"
	"encoding/binary"
)

// CTR encrypts or decrypts data in the Cryptopals CTR format: the keystream is
// E_k(nonce || counter), both 64-bit little-endian, counter starting at 0 and
// incremented per block. CTR turns a block cipher into a stream cipher: no
// padding, and encryption and decryption are the same XOR.
//
// Reusing a (key, nonce) pair reuses the keystream, which reduces CTR to a
// many-time pad (challenges 19 and 20).
func CTR(key []byte, nonce uint64, data []byte) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	var ctrBlock, ks [BlockSize]byte
	binary.LittleEndian.PutUint64(ctrBlock[:8], nonce)
	for i, counter := 0, uint64(0); i < len(data); i, counter = i+BlockSize, counter+1 {
		binary.LittleEndian.PutUint64(ctrBlock[8:], counter)
		block.Encrypt(ks[:], ctrBlock[:])
		end := min(i+BlockSize, len(data))
		subtle.XORBytes(out[i:end], data[i:end], ks[:end-i])
	}
	return out, nil
}
