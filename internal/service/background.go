package service

import (
	"sync"
	"time"
)

// backgroundWait bounds how long Run waits, after the panel stopped, for the
// goroutines it started. A goroutine that ignores its context must not keep
// the service from stopping; it is logged instead.
const backgroundWait = 8 * time.Second

// background tracks the goroutines started for one Run. Run returns only
// after they ended, so nothing writes to the data directory once Run
// returned (a service restart or a test cleanup would otherwise race with
// late writes such as the self-check report or the start marker).
type background struct {
	wg sync.WaitGroup
}

// spawn runs f in a goroutine that Run waits for before it returns.
func (r *Runtime) spawn(f func()) {
	r.bg.wg.Add(1)
	go func() {
		defer r.bg.wg.Done()
		f()
	}()
}

// waitBackground waits for the goroutines started with spawn, at most
// backgroundWait. It reports whether all of them ended.
func (r *Runtime) waitBackground() bool {
	done := make(chan struct{})
	go func() {
		r.bg.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(backgroundWait):
		r.logger.Warn("background work still running after the service stopped")
		return false
	}
}
