// Package mt19937 implements the 32-bit Mersenne Twister (Matsumoto &
// Nishimura, 1998), the default PRNG of many languages (Python's random, PHP's
// mt_rand, C++'s std::mt19937).
//
// It has excellent statistical properties and is NOT cryptographically
// secure: its whole state can be rebuilt from 624 consecutive outputs
// (challenge 23). Use crypto/rand for anything security-related.
package mt19937

const (
	n         = 624        // state size, in 32-bit words
	m         = 397        // middle word offset used by the twist
	matrixA   = 0x9908b0df // twist matrix coefficients
	upperMask = 0x80000000 // most significant bit
	lowerMask = 0x7fffffff // 31 least significant bits
	initMult  = 1812433253 // seeding multiplier
)

// MT is a Mersenne Twister generator. The zero value is not usable: create
// one with New or FromState.
type MT struct {
	state [n]uint32
	index int // next word of state to temper; n means "twist first"
}

// New returns a generator initialised with seed.
func New(seed uint32) *MT {
	mt := &MT{index: n}
	mt.state[0] = seed
	for i := 1; i < n; i++ {
		prev := mt.state[i-1]
		mt.state[i] = initMult*(prev^(prev>>30)) + uint32(i)
	}
	return mt
}

// FromState returns a generator that continues from a raw (untempered)
// internal state, as if the next call to Uint32 started a fresh twist.
func FromState(state [n]uint32) *MT {
	return &MT{state: state, index: n}
}

// StateSize is the number of 32-bit words in the internal state, which is
// also the number of consecutive outputs needed to clone a generator.
const StateSize = n

// Uint32 returns the next 32-bit output.
func (mt *MT) Uint32() uint32 {
	if mt.index >= n {
		mt.twist()
	}
	y := mt.state[mt.index]
	mt.index++
	return Temper(y)
}

// twist regenerates the whole state from the previous one.
func (mt *MT) twist() {
	for i := range n {
		y := mt.state[i]&upperMask | mt.state[(i+1)%n]&lowerMask
		next := y >> 1
		if y&1 != 0 {
			next ^= matrixA
		}
		mt.state[i] = mt.state[(i+m)%n] ^ next
	}
	mt.index = 0
}

// Temper is the output transformation applied to each state word. It is an
// invertible bijection on 32-bit words, which is what makes cloning possible.
func Temper(y uint32) uint32 {
	y ^= y >> 11
	y ^= y << 7 & 0x9d2c5680
	y ^= y << 15 & 0xefc60000
	y ^= y >> 18
	return y
}
