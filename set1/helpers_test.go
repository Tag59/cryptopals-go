package set1_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
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
		t.Errorf("SHA-256 = %x, want %s", sum, wantHex)
	}
}

// readLines returns the non-empty lines of a testdata file.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// readBase64File decodes a base64 testdata file (line breaks are ignored).
func readBase64File(t *testing.T, path string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.Join(readLines(t, path), ""))
	if err != nil {
		t.Fatalf("decode base64 %s: %v", path, err)
	}
	return b
}
