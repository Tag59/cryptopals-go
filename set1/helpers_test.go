package set1_test

import (
	"crypto/sha256"
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

// assertSHA256 checks a recovered plaintext against a pinned SHA-256 digest.
// Pinning digests keeps the expected answers out of the repository in clear
// (no spoilers) while still catching any regression.
func assertSHA256(t *testing.T, got []byte, wantHex string) {
	t.Helper()
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != wantHex {
		t.Errorf("plaintext SHA-256 = %x, want %s", sum, wantHex)
	}
}
