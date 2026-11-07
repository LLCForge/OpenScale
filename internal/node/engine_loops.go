package node

import (
	"log/slog"
	"sync"
	"time"
)

// loopsWait bounds how long Run waits for its background loops after the
// tunnel stopped; a loop that ignores its context is logged, not awaited
// forever.
const loopsWait = 8 * time.Second

// waitLoops waits for wg, at most loopsWait.
func waitLoops(wg *sync.WaitGroup, logger *slog.Logger) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(loopsWait):
		if logger != nil {
			logger.Warn("tunnel loops still running after the tunnel stopped")
		}
	}
}
