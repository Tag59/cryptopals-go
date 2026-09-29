package mdhash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test suite from RFC 1320, appendix A.5 (no MD4 in the standard library).
func TestMD4KnownAnswers(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
	}
	for _, tt := range tests {
		got := MD4([]byte(tt.in))
		if hex.EncodeToString(got[:]) != tt.want {
			t.Errorf("MD4(%q) = %x, want %s", tt.in, got, tt.want)
		}
	}
}

func TestMD4Padding(t *testing.T) {
	for n := range 3 * BlockSize {
		if total := n + len(MD4Padding(uint64(n))); total%BlockSize != 0 {
			t.Fatalf("len %d: padded length %d not block aligned", n, total)
		}
	}
}

// Resuming from the digest of M must equal hashing M || pad(M) || suffix.
func TestMD4Resume(t *testing.T) {
	msg, suffix := []byte("some message of arbitrary length"), []byte(";extension")
	glued := append(append(bytes.Clone(msg), MD4Padding(uint64(len(msg)))...), suffix...)
	processed := uint64(len(msg) + len(MD4Padding(uint64(len(msg)))))

	got, err := MD4Resume(MD4(msg), processed, suffix)
	if err != nil {
		t.Fatal(err)
	}
	if want := MD4(glued); got != want {
		t.Errorf("MD4Resume = %x, want %x", got, want)
	}
	if _, err := MD4Resume(MD4(msg), 10, suffix); err != ErrUnalignedLength {
		t.Errorf("unaligned length: got err %v, want ErrUnalignedLength", err)
	}
}
