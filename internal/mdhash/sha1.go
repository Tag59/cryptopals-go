package mdhash

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// SHA1Size is the size of a SHA-1 digest in bytes.
const SHA1Size = 20

var sha1Init = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}

// ErrUnalignedLength is returned when a resumed hash is told that a number of
// bytes not multiple of BlockSize was already processed.
var ErrUnalignedLength = errors.New("mdhash: processed length must be a multiple of the block size")

// SHA1 returns the SHA-1 digest of msg.
func SHA1(msg []byte) [SHA1Size]byte {
	return sha1Sum(sha1Init, msg, 0)
}

// SHA1Padding returns the padding SHA-1 appends to a message of msgLen bytes
// (the "glue" of a length-extension attack).
func SHA1Padding(msgLen uint64) []byte {
	return mdPadding(msgLen, binary.BigEndian)
}

// SHA1Resume continues a SHA-1 computation from a previous digest: it returns
// the digest of M || suffix, where M is a message of processedLen bytes
// (padding included, hence block-aligned) whose digest was `from`.
func SHA1Resume(from [SHA1Size]byte, processedLen uint64, suffix []byte) ([SHA1Size]byte, error) {
	if processedLen%BlockSize != 0 {
		return [SHA1Size]byte{}, ErrUnalignedLength
	}
	var h [5]uint32
	for i := range h {
		h[i] = binary.BigEndian.Uint32(from[4*i:])
	}
	return sha1Sum(h, suffix, processedLen), nil
}

// sha1Sum pads msg as if priorLen bytes had already been hashed into h, runs
// the compression function over each block and serialises the final state.
func sha1Sum(h [5]uint32, msg []byte, priorLen uint64) [SHA1Size]byte {
	data := append(append([]byte(nil), msg...), SHA1Padding(priorLen+uint64(len(msg)))...)
	for i := 0; i < len(data); i += BlockSize {
		sha1Block(&h, data[i:i+BlockSize])
	}
	var out [SHA1Size]byte
	for i, v := range h {
		binary.BigEndian.PutUint32(out[4*i:], v)
	}
	return out
}

// sha1Block is the SHA-1 compression function (FIPS 180-4, section 6.1.2).
func sha1Block(h *[5]uint32, block []byte) {
	var w [80]uint32
	for t := range 16 {
		w[t] = binary.BigEndian.Uint32(block[4*t:])
	}
	for t := 16; t < 80; t++ {
		w[t] = bits.RotateLeft32(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1)
	}

	a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
	for t := range 80 {
		var f, k uint32
		switch {
		case t < 20:
			f, k = b&c|^b&d, 0x5a827999
		case t < 40:
			f, k = b^c^d, 0x6ed9eba1
		case t < 60:
			f, k = b&c|b&d|c&d, 0x8f1bbcdc
		default:
			f, k = b^c^d, 0xca62c1d6
		}
		tmp := bits.RotateLeft32(a, 5) + f + e + k + w[t]
		a, b, c, d, e = tmp, a, bits.RotateLeft32(b, 30), c, d
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
}
