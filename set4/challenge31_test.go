package set4_test

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/Tag59/cryptopals-go/internal/aesutil"
	"github.com/Tag59/cryptopals-go/internal/hrclock"
	"github.com/Tag59/cryptopals-go/internal/mdhash"
)

// Challenge 31 — Implement and break HMAC-SHA1 with an artificial timing leak.
//
// The server checks HMAC-SHA1(key, file) against the signature it is sent
// with a byte-by-byte comparison that exits at the first mismatch and wastes
// some time after each matching byte. Response time is then proportional to
// the length of the correct prefix: for each position, try the 256 values and
// keep the slowest one. 20 × 256 requests instead of 2^160.
//
// The original challenge sleeps 50 ms per byte, which makes the attack take
// hours; 1 ms keeps the leak far above localhost noise while the test runs in
// about a minute. Skipped with -short.
//
// Lesson: comparing secrets must take a time independent of their contents
// (crypto/subtle.ConstantTimeCompare, hmac.Equal).
func TestChallenge31(t *testing.T) {
	if testing.Short() {
		t.Skip("timing attack takes about a minute")
	}
	breakTimingLeak(t, time.Millisecond, 1)
}

// breakTimingLeak starts a leaky server with the given per-byte delay and
// recovers a valid signature for a file, measuring each candidate `samples`
// times.
func breakTimingLeak(t *testing.T, delay time.Duration, samples int) {
	srv := &leakyHMACServer{key: aesutil.RandomBytes(16), delay: delay}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	const file = "passwd"
	oracle := &timingOracle{client: ts.Client(), base: ts.URL, file: file}

	sig, err := recoverSignature(oracle, samples, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if want := mdhash.HMACSHA1(srv.key, []byte(file)); string(sig) != string(want[:]) {
		t.Fatalf("recovered %x, want %x", sig, want)
	}
}

// recoverSignature finds the signature byte by byte. For each position, every
// candidate is timed `samples` times (interleaved, so that a burst of noise
// spreads over all of them) and scored by its median; the eight best are then
// timed again more thoroughly, so that a right byte pushed down by a burst of
// OS scheduling noise still gets its chance.
//
// A wrong guess is self-revealing: past it, no candidate stands out from the
// bulk any more. When the winner's lead over the bulk falls below half the
// typical (median) lead of the positions already found, the position is
// measured again, then, if it still fails, the attack steps back and redoes
// the previous one. The last byte leaks nothing useful: it is simply the one
// the server accepts.
func recoverSignature(o *timingOracle, samples int, logf func(string, ...any)) ([]byte, error) {
	sig := make([]byte, mdhash.SHA1Size)
	last := len(sig) - 1
	leads := make([]time.Duration, last) // winner's lead over the bulk, per position
	retried := false
	for i, budget := 0, 8*len(sig); ; budget-- {
		if budget == 0 {
			return nil, errTooNoisy
		}
		if i == last {
			ok, err := o.findLast(sig)
			if err != nil {
				return nil, err
			}
			if ok {
				return sig, nil
			}
			logf("no last byte accepted, stepping back")
			i--
			continue
		}

		scores, err := o.medians(sig, i, allBytes(), samples)
		if err != nil {
			return nil, err
		}
		bulk := slices.Sorted(slices.Values(scores[:]))[128]
		top := allBytes()
		slices.SortFunc(top, func(a, b byte) int { return int(scores[b] - scores[a]) })
		top = top[:8]
		if scores, err = o.medians(sig, i, top, 5*samples); err != nil {
			return nil, err
		}
		best := slices.MaxFunc(top, func(a, b byte) int { return int(scores[a] - scores[b]) })

		lead := scores[best] - bulk
		if i > 0 && lead < slices.Sorted(slices.Values(leads[:i]))[i/2]/2 {
			if retried {
				logf("byte %2d: no candidate stands out (%v), stepping back", i, lead)
				i--
			} else {
				logf("byte %2d: no candidate stands out (%v), measuring again", i, lead)
			}
			retried = !retried
			continue
		}
		leads[i], retried = lead, false
		sig[i] = best
		logf("byte %2d = %02x (%v, lead %v)", i, best, scores[best], lead)
		i++
	}
}

// findLast sets the last byte of sig to the value the server accepts, if any.
func (o *timingOracle) findLast(sig []byte) (bool, error) {
	for c := range 256 {
		sig[len(sig)-1] = byte(c)
		ok, _, err := o.try(sig)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

var errTooNoisy = errors.New("timing measurements too noisy: gave up after too many step-backs")

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// timingOracle sends signatures to the leaky server and times its answers.
type timingOracle struct {
	client *http.Client
	base   string
	file   string
}

// medians times sig with sig[pos] set to each candidate, n times each, and
// returns the median duration per candidate.
func (o *timingOracle) medians(sig []byte, pos int, candidates []byte, n int) ([256]time.Duration, error) {
	var times [256][]time.Duration
	for range n {
		for _, c := range candidates {
			sig[pos] = c
			_, d, err := o.try(sig)
			if err != nil {
				return [256]time.Duration{}, err
			}
			times[c] = append(times[c], d)
		}
	}
	var med [256]time.Duration
	for _, c := range candidates {
		slices.Sort(times[c])
		med[c] = times[c][n/2]
	}
	return med, nil
}

// try submits sig and reports whether the server accepted it and how long
// the round trip took.
func (o *timingOracle) try(sig []byte) (bool, time.Duration, error) {
	u := o.base + "/test?" + url.Values{"file": {o.file}, "signature": {hex.EncodeToString(sig)}}.Encode()
	start := hrclock.Now()
	resp, err := o.client.Get(u)
	if err != nil {
		return false, 0, err
	}
	d := hrclock.Since(start)
	io.Copy(io.Discard, resp.Body) // drain, so the connection is reused
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK, d, nil
}

// leakyHMACServer answers /test?file=...&signature=... with 200 if signature
// is the hex HMAC-SHA1 of file, 500 otherwise — using a leaky comparison.
type leakyHMACServer struct {
	key   []byte
	delay time.Duration
}

func (s *leakyHMACServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sig, err := hex.DecodeString(r.URL.Query().Get("signature"))
	if err != nil {
		http.Error(w, "bad signature encoding", http.StatusBadRequest)
		return
	}
	want := mdhash.HMACSHA1(s.key, []byte(r.URL.Query().Get("file")))
	if !insecureCompare(want[:], sig, s.delay) {
		http.Error(w, "invalid signature", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// insecureCompare exits at the first differing byte and spends `delay` after
// each matching one.
func insecureCompare(a, b []byte, delay time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
		hrclock.Spin(delay)
	}
	return true
}
