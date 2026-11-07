package winapp

import "testing"

func TestClearDecision(t *testing.T) {
	cases := []struct {
		set, now uint32
		want     bool
	}{
		{5, 5, true},  // nothing copied since: clear
		{5, 6, false}, // the user copied something else: keep it
		{0, 0, false}, // sequence unknown: never clear blindly
		{7, 0, false},
	}
	for _, c := range cases {
		if got := clearDecision(c.set, c.now); got != c.want {
			t.Errorf("clearDecision(%d, %d) = %v, want %v", c.set, c.now, got, c.want)
		}
	}
}
