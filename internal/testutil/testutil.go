// Package testutil holds the helpers shared by the challenge tests: decoding
// fixtures and checking answers against pinned digests.
package testutil

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// MustHex decodes a hex literal, failing the test on malformed input.
func MustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// MustBase64 decodes a standard base64 string, failing the test on error.
func MustBase64(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		tb.Fatalf("decode base64: %v", err)
	}
	return b
}

// AssertSHA256 checks a recovered value against a pinned SHA-256 digest.
// Pinning digests keeps the expected answers out of the repository in clear
// (no spoilers) while still catching any regression.
func AssertSHA256(tb testing.TB, got []byte, wantHex string) {
	tb.Helper()
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != wantHex {
		tb.Errorf("SHA-256 = %x, want %s", sum, wantHex)
	}
}

// ReadLines returns the non-empty, trimmed lines of a testdata file.
func ReadLines(tb testing.TB, path string) []string {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// ReadBase64File decodes a base64 testdata file (line breaks are ignored).
func ReadBase64File(tb testing.TB, path string) []byte {
	tb.Helper()
	return MustBase64(tb, strings.Join(ReadLines(tb, path), ""))
}
