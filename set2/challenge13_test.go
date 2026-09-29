package set2_test

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
)

// Challenge 13 — ECB cut-and-paste.
//
// The server issues encrypted profiles "email=...&uid=10&role=user" and
// trusts whatever role it decrypts. It strips '&' and '=' from the email, so
// we cannot inject "&role=admin" directly. But ECB blocks are independent:
// ciphertext blocks can be cut from one message and pasted into another, and
// each still decrypts to its own plaintext.
//
//  1. Choose an email so that "admin" + valid PKCS#7 padding fills a block by
//     itself, and keep that ciphertext block.
//  2. Choose an email length so that "role=" ends exactly at a block boundary.
//  3. Replace the last block (holding "user" + padding) with the saved block.
//
// Lesson: encryption is not integrity. Without a MAC, an attacker rearranges
// ciphertext and the server happily decrypts a message nobody ever encrypted.
func TestChallenge13(t *testing.T) {
	srv := newProfileServer()
	const bs = aesutil.BlockSize

	// Block 1 = "admin" + 11 × 0x0b, since "email=" + 10 bytes fills block 0.
	adminBlock, err := aesutil.PKCS7Pad([]byte("admin"), bs)
	if err != nil {
		t.Fatal(err)
	}
	ct1, err := srv.encryptProfile(strings.Repeat("A", bs-len("email=")) + string(adminBlock))
	if err != nil {
		t.Fatal(err)
	}
	pasted := ct1[bs : 2*bs]

	// "email=" (6) + 13-byte email + "&uid=10&role=" (13) = 32 = two blocks.
	ct2, err := srv.encryptProfile("foooo@bar.com")
	if err != nil {
		t.Fatal(err)
	}
	forged := append(bytes.Clone(ct2[:2*bs]), pasted...)

	profile, err := srv.decryptProfile(forged)
	if err != nil {
		t.Fatalf("decryptProfile: %v", err)
	}
	if got := profile.Get("role"); got != "admin" {
		t.Errorf("role = %q, want admin (profile %v)", got, profile)
	}
	if got := profile.Get("email"); got != "foooo@bar.com" {
		t.Errorf("email = %q, want foooo@bar.com", got)
	}
}

// profileServer holds the secret key; the attacker only sees its two methods.
type profileServer struct{ key []byte }

func newProfileServer() *profileServer {
	return &profileServer{key: aesutil.RandomBytes(16)}
}

// profileFor encodes a user profile, removing the metacharacters '&' and '='
// from the email so they cannot be injected.
func profileFor(email string) string {
	email = strings.NewReplacer("&", "", "=", "").Replace(email)
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}

func (s *profileServer) encryptProfile(email string) ([]byte, error) {
	pt, err := aesutil.PKCS7Pad([]byte(profileFor(email)), aesutil.BlockSize)
	if err != nil {
		return nil, err
	}
	return aesutil.ECBEncrypt(s.key, pt)
}

func (s *profileServer) decryptProfile(ct []byte) (url.Values, error) {
	padded, err := aesutil.ECBDecrypt(s.key, ct)
	if err != nil {
		return nil, err
	}
	pt, err := aesutil.PKCS7Unpad(padded, aesutil.BlockSize)
	if err != nil {
		return nil, err
	}
	return parseKV(string(pt))
}

// parseKV parses the "k=v&k2=v2" format from the statement. It is a plain
// split, without URL decoding, so the forged bytes are read back literally.
func parseKV(s string) (url.Values, error) {
	out := url.Values{}
	for pair := range strings.SplitSeq(s, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("malformed pair %q", pair)
		}
		out.Add(k, v)
	}
	return out, nil
}

func TestParseKV(t *testing.T) {
	got, err := parseKV("foo=bar&baz=qux&zap=zazzle")
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("foo") != "bar" || got.Get("baz") != "qux" || got.Get("zap") != "zazzle" {
		t.Errorf("parseKV = %v", got)
	}
	if got := profileFor("foo@bar.com&role=admin"); got != "email=foo@bar.comroleadmin&uid=10&role=user" {
		t.Errorf("profileFor did not strip metacharacters: %q", got)
	}
}
