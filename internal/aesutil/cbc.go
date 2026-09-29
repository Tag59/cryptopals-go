package aesutil

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

// ErrInvalidIV is returned when an IV is not exactly one block long.
var ErrInvalidIV = errors.New("aesutil: IV must be exactly one block long")

// CBCEncrypt encrypts block-aligned pt in CBC mode:
//
//	C[i] = E_k(P[i] ^ C[i-1]),  C[-1] = IV
//
// Chaining hides repeated blocks (unlike ECB), but CBC alone provides no
// integrity: ciphertext bits can be flipped to control the plaintext
// (challenge 16), and a padding error leaks the plaintext (challenge 17).
func CBCEncrypt(key, iv, pt []byte) ([]byte, error) {
	block, err := checkCBC(key, iv, pt)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(pt))
	prev := iv
	for i := 0; i < len(pt); i += BlockSize {
		cur := out[i : i+BlockSize]
		subtle.XORBytes(cur, pt[i:i+BlockSize], prev)
		block.Encrypt(cur, cur)
		prev = cur
	}
	return out, nil
}

// CBCDecrypt is the inverse of CBCEncrypt: P[i] = D_k(C[i]) ^ C[i-1].
// Note that P[i] depends linearly on C[i-1]: flipping a bit of C[i-1] flips
// the same bit of P[i] (and garbles P[i-1]).
func CBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := checkCBC(key, iv, ct)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	prev := iv
	for i := 0; i < len(ct); i += BlockSize {
		cur := ct[i : i+BlockSize]
		block.Decrypt(out[i:i+BlockSize], cur)
		subtle.XORBytes(out[i:i+BlockSize], out[i:i+BlockSize], prev)
		prev = cur
	}
	return out, nil
}

// checkCBC validates the CBC inputs and returns the AES block for key.
func checkCBC(key, iv, data []byte) (cipher.Block, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("%w (got %d bytes)", ErrInvalidIV, len(iv))
	}
	if len(data)%BlockSize != 0 {
		return nil, fmt.Errorf("%w (%d bytes)", ErrNotBlockAligned, len(data))
	}
	return block, nil
}
