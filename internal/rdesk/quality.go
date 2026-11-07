package rdesk

import "time"

// Adaptive quality (#121). The server keeps at most frameWindow frames
// unacknowledged and times each frame from the start of sending to its
// acknowledgement. The part of that time above the link's base round trip
// is the transfer time. When frames keep needing more than twice the
// frame budget the controller halves the frame rate down to minFPS and
// then doubles the downscale factor up to 4; when frames keep arriving
// well within budget it restores resolution first and then frame rate.
// Slow links also get the stronger flate level. Everything stays
// lossless at the chosen resolution.

const (
	minFPS        = 2
	slowStreak    = 3
	fastStreak    = 10
	rttWindow     = 64
	slowBandwidth = 1 << 20 // bytes per second below which flateSmall is used
	bwSampleMin   = 64 << 10
)

type quality struct {
	maxFPS     int
	fixedScale int // 0: adaptive
	fps        int
	scale      int
	level      int

	slow, fast int
	minRTT     time.Duration
	winMin     time.Duration
	samples    int
	bw         float64 // bytes per second, smoothed
}

func newQuality(maxFPS, fixedScale int) *quality {
	q := &quality{maxFPS: max(maxFPS, minFPS), fixedScale: fixedScale, level: flateFast}
	q.fps = q.maxFPS
	q.scale = 1
	if fixedScale != 0 {
		q.scale = fixedScale
	}
	return q
}

func (q *quality) budget() time.Duration { return time.Second / time.Duration(q.fps) }

// setLimits applies a client hint: a lower frame rate ceiling and a fixed
// or adaptive scale. It reports whether the scale changed.
func (q *quality) setLimits(maxFPS, scale, serverMax int) bool {
	if maxFPS <= 0 || maxFPS > serverMax {
		maxFPS = serverMax
	}
	q.maxFPS = max(maxFPS, minFPS)
	q.fps = min(q.fps, q.maxFPS)
	old := q.scale
	q.fixedScale = scale
	if scale != 0 {
		q.scale = scale
	}
	q.slow, q.fast = 0, 0
	return q.scale != old
}

// observe records one acknowledged frame of n bytes that took elapsed
// from send to acknowledgement. It reports whether the scale changed (the
// caller must then resend a full frame at the new size).
func (q *quality) observe(n int, elapsed time.Duration) bool {
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}
	if q.minRTT == 0 || elapsed < q.minRTT {
		q.minRTT = elapsed
	}
	if q.winMin == 0 || elapsed < q.winMin {
		q.winMin = elapsed
	}
	q.samples++
	if q.samples >= rttWindow {
		// Forget an old minimum so a route change is noticed.
		q.minRTT, q.winMin, q.samples = q.winMin, 0, 0
	}
	transfer := elapsed - q.minRTT
	if n >= bwSampleMin {
		rate := float64(n) / elapsed.Seconds()
		if q.bw == 0 {
			q.bw = rate
		} else {
			q.bw = 0.8*q.bw + 0.2*rate
		}
		if q.bw < slowBandwidth {
			q.level = flateSmall
		} else {
			q.level = flateFast
		}
	}
	b := q.budget()
	switch {
	case transfer > 2*b:
		q.slow++
		q.fast = 0
	case transfer < b/3:
		q.fast++
		q.slow = 0
	default:
		q.slow, q.fast = 0, 0
	}
	if q.slow >= slowStreak {
		q.slow = 0
		if q.fps > minFPS {
			q.fps = max(minFPS, q.fps/2)
			return false
		}
		if q.fixedScale == 0 && q.scale < 4 {
			q.scale *= 2
			return true
		}
		return false
	}
	if q.fast >= fastStreak {
		q.fast = 0
		if q.fixedScale == 0 && q.scale > 1 {
			q.scale /= 2
			return true
		}
		if q.fps < q.maxFPS {
			q.fps = min(q.maxFPS, q.fps+max(1, q.fps/4))
		}
	}
	return false
}
