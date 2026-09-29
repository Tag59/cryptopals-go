package mdhash

import (
	"encoding/binary"
	"math/bits"
)

// MD4Size is the size of an MD4 digest in bytes.
const MD4Size = 16

var md4Init = [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}

// MD4 returns the MD4 digest of msg (RFC 1320).
func MD4(msg []byte) [MD4Size]byte {
	return md4Sum(md4Init, msg, 0)
}

// MD4Padding returns the padding MD4 appends to a message of msgLen bytes.
// Same layout as SHA-1, but the length is little-endian.
func MD4Padding(msgLen uint64) []byte {
	return mdPadding(msgLen, binary.LittleEndian)
}

// MD4Resume continues an MD4 computation from a previous digest: it returns
// the digest of M || suffix, where M is a message of processedLen bytes
// (padding included, hence block-aligned) whose digest was `from`.
func MD4Resume(from [MD4Size]byte, processedLen uint64, suffix []byte) ([MD4Size]byte, error) {
	if processedLen%BlockSize != 0 {
		return [MD4Size]byte{}, ErrUnalignedLength
	}
	var h [4]uint32
	for i := range h {
		h[i] = binary.LittleEndian.Uint32(from[4*i:])
	}
	return md4Sum(h, suffix, processedLen), nil
}

// md4Sum pads msg as if priorLen bytes had already been hashed into h, runs
// the compression function over each block and serialises the final state.
func md4Sum(h [4]uint32, msg []byte, priorLen uint64) [MD4Size]byte {
	data := append(append([]byte(nil), msg...), MD4Padding(priorLen+uint64(len(msg)))...)
	for i := 0; i < len(data); i += BlockSize {
		md4Block(&h, data[i:i+BlockSize])
	}
	var out [MD4Size]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out
}

// Word order and rotation amounts of the three MD4 rounds (RFC 1320, 3.4).
var (
	md4Order = [3][16]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15},
		{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15},
	}
	md4Shift = [3][4]int{{3, 7, 11, 19}, {3, 5, 9, 13}, {3, 9, 11, 15}}
	md4K     = [3]uint32{0, 0x5a827999, 0x6ed9eba1}
)

// md4Block is the MD4 compression function. Each step updates one register
// and rotates their roles (a, b, c, d) -> (d, a, b, c).
func md4Block(h *[4]uint32, block []byte) {
	var x [16]uint32
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(block[4*i:])
	}

	a, b, c, d := h[0], h[1], h[2], h[3]
	for r := range 3 {
		for i := range 16 {
			var f uint32
			switch r {
			case 0:
				f = b&c | ^b&d
			case 1:
				f = b&c | b&d | c&d
			default:
				f = b ^ c ^ d
			}
			t := bits.RotateLeft32(a+f+x[md4Order[r][i]]+md4K[r], md4Shift[r][i%4])
			a, b, c, d = d, t, b, c
		}
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
}
