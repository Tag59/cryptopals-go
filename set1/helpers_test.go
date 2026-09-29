package set1_test

import (
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex literal, failing the test on malformed input.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}
