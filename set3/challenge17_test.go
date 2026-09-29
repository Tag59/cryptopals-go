package set3_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/testutil"
)

// Challenge 17 — The CBC padding oracle.
//
// The server decrypts any (IV, ciphertext) we send and only tells us whether
// the PKCS#7 padding was valid. That single bit is enough to decrypt
// everything. Full write-up in docs/17-cbc-padding-oracle.md.
//
// For a target block C with predecessor P (previous block or IV), CBC gives
// plaintext = D(C) ^ P. We send (P', C) with a forged P'. For the last byte,
// we try all 256 values of P'[15] until the padding is valid, which (almost
// always) means D(C)[15] ^ P'[15] == 0x01, revealing D(C)[15]. We then set
// the known tail to 0x02 and attack byte 14, and so on down to byte 0.
// Finally, plaintext = D(C) ^ P. At most 256 queries per byte.
//
// Lesson: any observable difference in how decryption fails (error message,
// status code, timing) is an oracle. Authenticate before decrypting.
func TestChallenge17(t *testing.T) {
	lines := testutil.ReadLines(t, "testdata/17.txt")
	srv := newPaddingServer()

	for i, line := range lines {
		want := testutil.MustBase64(t, line)
		iv, ct, err := srv.encrypt(want)
		if err != nil {
			t.Fatal(err)
		}

		srv.queries = 0
		got, err := paddingOracleAttack(srv.validPadding, iv, ct, aesutil.BlockSize)
		if err != nil {
			t.Fatalf("string %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("string %d: recovered plaintext does not match", i)
		}
		t.Logf("string %d: %d bytes recovered in %d oracle queries", i, len(got), srv.queries)
	}
}

// The accidental "02 02" case happens only once in 256 blocks, so force it
// with a synthetic oracle: D(C)[14] = 0x02 makes forged byte 14 (initially 0)
// decrypt to 0x02, and the guess yielding a final 0x02 then looks valid too.
func TestRecoverIntermediateAccidentalPadding(t *testing.T) {
	const bs = aesutil.BlockSize
	inter := aesutil.RandomBytes(bs)
	inter[bs-2] = 0x02
	oracle := func(iv, _ []byte) bool {
		pt := make([]byte, bs)
		for i := range pt {
			pt[i] = inter[i] ^ iv[i]
		}
		_, err := aesutil.PKCS7Unpad(pt, bs)
		return err == nil
	}

	got, err := recoverIntermediate(oracle, make([]byte, bs), bs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, inter) {
		t.Errorf("recoverIntermediate = %x, want %x", got, inter)
	}
}

// paddingOracle reports whether (iv, ct) decrypts to validly padded plaintext.
type paddingOracle func(iv, ct []byte) bool

// paddingOracleAttack decrypts a CBC ciphertext using only a padding oracle.
func paddingOracleAttack(oracle paddingOracle, iv, ct []byte, bs int) ([]byte, error) {
	if len(ct) == 0 || len(ct)%bs != 0 || len(iv) != bs {
		return nil, errors.New("ciphertext or IV not block aligned")
	}
	var padded []byte
	prev := iv
	for i := 0; i < len(ct); i += bs {
		blk := ct[i : i+bs]
		inter, err := recoverIntermediate(oracle, blk, bs)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i/bs, err)
		}
		for j := range bs {
			padded = append(padded, inter[j]^prev[j])
		}
		prev = blk
	}
	return aesutil.PKCS7Unpad(padded, bs)
}

// recoverIntermediate finds D_k(blk), the block-cipher output before the CBC
// XOR, one byte at a time from the last byte to the first.
func recoverIntermediate(oracle paddingOracle, blk []byte, bs int) ([]byte, error) {
	inter := make([]byte, bs)
	forged := make([]byte, bs)
	for pos := bs - 1; pos >= 0; pos-- {
		pad := byte(bs - pos)
		// Make the already-known tail decrypt to the target padding value.
		for k := pos + 1; k < bs; k++ {
			forged[k] = inter[k] ^ pad
		}
		found := false
		for g := range 256 {
			forged[pos] = byte(g)
			if !oracle(forged, blk) {
				continue
			}
			// On the last byte, valid padding may be 02 02 (or 03 03 03...)
			// by accident rather than 01. Changing the byte before it breaks
			// any longer padding but keeps a genuine 01 valid.
			if pos == bs-1 {
				forged[pos-1] ^= 0xff
				genuine := oracle(forged, blk)
				forged[pos-1] ^= 0xff
				if !genuine {
					continue
				}
			}
			inter[pos] = byte(g) ^ pad
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("no valid padding for byte %d", pos)
		}
	}
	return inter, nil
}

// paddingServer encrypts under a secret key and leaks padding validity.
type paddingServer struct {
	key     []byte
	queries int
}

func newPaddingServer() *paddingServer {
	return &paddingServer{key: aesutil.RandomBytes(16)}
}

// encrypt returns a fresh random IV and the CBC encryption of pt.
func (s *paddingServer) encrypt(pt []byte) (iv, ct []byte, err error) {
	padded, err := aesutil.PKCS7Pad(pt, aesutil.BlockSize)
	if err != nil {
		return nil, nil, err
	}
	iv = aesutil.RandomBytes(aesutil.BlockSize)
	ct, err = aesutil.CBCEncrypt(s.key, iv, padded)
	return iv, ct, err
}

// validPadding is the oracle: it reveals one bit, whether unpadding succeeded.
func (s *paddingServer) validPadding(iv, ct []byte) bool {
	s.queries++
	pt, err := aesutil.CBCDecrypt(s.key, iv, ct)
	if err != nil {
		return false
	}
	_, err = aesutil.PKCS7Unpad(pt, aesutil.BlockSize)
	return err == nil
}
