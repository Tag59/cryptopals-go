// Package mdhash implements SHA-1 and MD4 from scratch, exposing what the
// standard library deliberately hides: the ability to resume hashing from an
// arbitrary internal state. That is exactly what a length-extension attack
// needs (challenges 29 and 30).
//
// Both are Merkle–Damgård constructions: the message is padded, cut into
// 64-byte blocks, and a compression function updates a small state block
// after block. The final digest IS the final state, so anyone holding a digest
// can keep hashing from where it stopped. Both hashes are broken for
// collision resistance; they are here to be attacked, not used.
package mdhash

import "encoding/binary"

// BlockSize is the block size of SHA-1 and MD4, in bytes.
const BlockSize = 64

// mdPadding returns the Merkle–Damgård padding for a message of msgLen bytes:
// 0x80, zeros up to 56 mod 64, then the bit length on 8 bytes. SHA-1 encodes
// the length big-endian, MD4 little-endian.
func mdPadding(msgLen uint64, order binary.ByteOrder) []byte {
	zeros := (BlockSize + 55 - int(msgLen%BlockSize)) % BlockSize
	pad := make([]byte, 1+zeros+8)
	pad[0] = 0x80
	order.PutUint64(pad[1+zeros:], msgLen*8)
	return pad
}
