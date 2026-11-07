package trust

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"sync"
)

// Randomness health check (#17, ADR-0060). Before the first key is made
// from the operating system CSPRNG, two samples are drawn and checked for
// failures that would make keys predictable: a source that returns the
// same bytes twice, a stuck byte, or output far from half ones. These are
// sanity checks for a broken source, not a statistical test suite; a
// healthy source fails them with probability below 2^-40.

// ErrRandomUnhealthy is returned when the random source fails the health
// check. No key is generated from it.
var ErrRandomUnhealthy = errors.New("random number generator failed its health check")

const (
	healthSampleSize = 256
	// healthMaxRun is the shortest rejected run of one repeated byte.
	healthMaxRun = 8
	// healthMinDistinct is far below the ~162 distinct values expected in
	// 256 random bytes.
	healthMinDistinct = 64
	// healthOnesSlack is eight standard deviations of the number of ones in
	// 2048 random bits around the mean of 1024.
	healthOnesSlack = 181
)

// CheckRandom draws two samples from r and rejects a broken source.
func CheckRandom(r io.Reader) error {
	a := make([]byte, healthSampleSize)
	b := make([]byte, healthSampleSize)
	defer wipe(a)
	defer wipe(b)
	if _, err := io.ReadFull(r, a); err != nil {
		return fmt.Errorf("%w: %v", ErrRandomUnhealthy, err)
	}
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("%w: %v", ErrRandomUnhealthy, err)
	}
	if bytes.Equal(a, b) {
		return fmt.Errorf("%w: repeated output", ErrRandomUnhealthy)
	}
	for _, s := range [][]byte{a, b} {
		if err := checkSample(s); err != nil {
			return err
		}
	}
	return nil
}

func checkSample(s []byte) error {
	ones := 0
	run, longest := 1, 1
	var seen [256]bool
	distinct := 0
	for i, c := range s {
		ones += bits.OnesCount8(c)
		if !seen[c] {
			seen[c] = true
			distinct++
		}
		if i > 0 && c == s[i-1] {
			run++
			longest = max(longest, run)
		} else {
			run = 1
		}
	}
	mean := len(s) * 4
	switch {
	case longest >= healthMaxRun:
		return fmt.Errorf("%w: stuck output", ErrRandomUnhealthy)
	case distinct < healthMinDistinct:
		return fmt.Errorf("%w: too few distinct values", ErrRandomUnhealthy)
	case ones < mean-healthOnesSlack || ones > mean+healthOnesSlack:
		return fmt.Errorf("%w: biased output", ErrRandomUnhealthy)
	}
	return nil
}

var systemRandom struct {
	once sync.Once
	err  error
}

// CheckSystemRandom checks the operating system CSPRNG once per process
// and returns the cached result afterwards.
func CheckSystemRandom() error {
	systemRandom.once.Do(func() { systemRandom.err = CheckRandom(rand.Reader) })
	return systemRandom.err
}

// checkRandomSource runs the system check when r is the system CSPRNG.
// Other readers (deterministic test sources) are the caller's choice.
func checkRandomSource(r io.Reader) error {
	// No key is made by primitives that failed their known answers (#531).
	if _, err := CryptoSelfTest(); err != nil {
		return err
	}
	if r != rand.Reader {
		return nil
	}
	return CheckSystemRandom()
}
