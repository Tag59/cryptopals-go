// Package xorutil provides the XOR primitives and encoding helpers shared by
// the challenges. It is intentionally low-level and not meant for production.
package xorutil

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// HexToBase64 decodes a hex string and re-encodes the raw bytes as standard
// base64. Cryptopals rule: always operate on raw bytes, never on encoded
// strings — encodings are only for display and transport.
func HexToBase64(s string) (string, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
