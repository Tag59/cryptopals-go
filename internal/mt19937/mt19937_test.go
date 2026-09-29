package mt19937

import "testing"

// Reference values from the original mt19937ar.c with init_genrand, and the
// C++ standard's requirement that the 10000th output of a default-seeded
// std::mt19937 (seed 5489) is 4123659995.
func TestKnownAnswers(t *testing.T) {
	cases := []struct {
		seed uint32
		want []uint32
	}{
		{5489, []uint32{3499211612, 581869302, 3890346734, 3586334585, 545404204}},
		{1, []uint32{1791095845, 4282876139, 3093770124, 4005303368, 491263}},
	}
	for _, c := range cases {
		mt := New(c.seed)
		for i, want := range c.want {
			if got := mt.Uint32(); got != want {
				t.Errorf("seed %d output %d = %d, want %d", c.seed, i, got, want)
			}
		}
	}

	mt := New(5489)
	var got uint32
	for range 10000 {
		got = mt.Uint32()
	}
	if got != 4123659995 {
		t.Errorf("10000th output for seed 5489 = %d, want 4123659995", got)
	}
}
