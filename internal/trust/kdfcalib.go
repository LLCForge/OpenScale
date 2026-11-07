package trust

import (
	"math"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id calibration (#11, ADR-0060). A new root key is sealed with the
// strongest parameters this machine computes within a target time, never
// below DefaultArgon2 (RFC 9106's second recommendation). Memory is raised
// first, as RFC 9106 advises, but only to calibrationMaxMemory: a backup
// must still open on a small device (a single-board computer) that the
// owner restores it on. Time is raised after that.

const (
	// DefaultKDFTarget is the unlock time aimed for on the owner's device.
	DefaultKDFTarget = time.Second
	// calibrationMaxMemory is 128 MiB.
	calibrationMaxMemory = 128 * 1024
	// calibrationMaxTime keeps the unlock bounded on a slower device.
	calibrationMaxTime = 8
)

// CalibrateArgon2 measures this machine and returns parameters that take
// about target to derive, never weaker than DefaultArgon2.
func CalibrateArgon2(target time.Duration) Argon2Params {
	return calibrateArgon2(target, measureArgon2)
}

func calibrateArgon2(target time.Duration, measure func(Argon2Params) time.Duration) Argon2Params {
	p := DefaultArgon2
	if target <= 0 {
		return p
	}
	d := measure(p)
	if d >= target {
		return p
	}
	if d > 0 && d*2 <= target && p.MemoryKiB < calibrationMaxMemory {
		q := p
		q.MemoryKiB = calibrationMaxMemory
		p, d = q, measure(q)
		if d >= target {
			return p
		}
	}
	if d <= 0 {
		return p
	}
	t := math.Ceil(float64(p.Time) * float64(target) / float64(d))
	p.Time = uint32(min(max(t, float64(p.Time)), calibrationMaxTime))
	return p
}

func measureArgon2(p Argon2Params) time.Duration {
	salt := make([]byte, saltSize)
	start := time.Now()
	k := argon2.IDKey([]byte("openscale-calibration"), salt, p.Time, p.MemoryKiB, p.Threads, 32)
	elapsed := time.Since(start)
	wipe(k)
	return elapsed
}

// StrongerArgon2 returns the field-wise maximum of a and b, so re-sealing
// a key never lowers the cost it already had.
func StrongerArgon2(a, b Argon2Params) Argon2Params {
	return Argon2Params{
		Time:      max(a.Time, b.Time),
		MemoryKiB: max(a.MemoryKiB, b.MemoryKiB),
		Threads:   max(a.Threads, b.Threads),
	}
}

// WeakerThan reports whether p costs less than q in time or memory.
func (p Argon2Params) WeakerThan(q Argon2Params) bool {
	return p.Time < q.Time || p.MemoryKiB < q.MemoryKiB
}

// KDFParams returns the Argon2id parameters the key was sealed with.
func (s *SealedRootKey) KDFParams() Argon2Params { return s.KDF }
