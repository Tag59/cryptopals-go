package mdhash

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"testing"
)

// Cross-check against crypto/sha1 on every length around block boundaries,
// where padding bugs hide.
func TestSHA1MatchesStdlib(t *testing.T) {
	for n := range 3*BlockSize + 1 {
		msg := make([]byte, n)
		rand.Read(msg)
		if got, want := SHA1(msg), sha1.Sum(msg); got != want {
			t.Fatalf("len %d: SHA1 = %x, want %x", n, got, want)
		}
	}
}

func TestSHA1Padding(t *testing.T) {
	for n := range 3 * BlockSize {
		if total := n + len(SHA1Padding(uint64(n))); total%BlockSize != 0 {
			t.Fatalf("len %d: padded length %d not block aligned", n, total)
		}
	}
}

// Resuming from the digest of M must equal hashing M || pad(M) || suffix.
func TestSHA1Resume(t *testing.T) {
	msg, suffix := []byte("some message of arbitrary length"), []byte(";extension")
	glued := append(append(bytes.Clone(msg), SHA1Padding(uint64(len(msg)))...), suffix...)
	processed := uint64(len(msg) + len(SHA1Padding(uint64(len(msg)))))

	got, err := SHA1Resume(SHA1(msg), processed, suffix)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha1.Sum(glued); got != want {
		t.Errorf("SHA1Resume = %x, want %x", got, want)
	}
	if _, err := SHA1Resume(SHA1(msg), 10, suffix); err != ErrUnalignedLength {
		t.Errorf("unaligned length: got err %v, want ErrUnalignedLength", err)
	}
}
