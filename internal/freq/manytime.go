package freq

// BreakManyTimePad recovers a keystream reused across several ciphertexts
// (e.g. CTR with a fixed nonce). Byte j of every ciphertext was XORed with the
// same keystream byte ks[j], so column j is a single-byte XOR problem.
// Ciphertexts may differ in length: column j uses every ciphertext longer than
// j, so late columns rest on few samples and are less reliable.
func BreakManyTimePad(cts [][]byte) ([]byte, error) {
	maxLen := 0
	for _, ct := range cts {
		maxLen = max(maxLen, len(ct))
	}
	if maxLen == 0 {
		return nil, ErrEmptyInput
	}
	ks := make([]byte, maxLen)
	col := make([]byte, 0, len(cts))
	for j := range maxLen {
		col = col[:0]
		for _, ct := range cts {
			if j < len(ct) {
				col = append(col, ct[j])
			}
		}
		r, err := BreakSingleByteXOR(col)
		if err != nil {
			return nil, err
		}
		ks[j] = r.Key
	}
	return ks, nil
}
