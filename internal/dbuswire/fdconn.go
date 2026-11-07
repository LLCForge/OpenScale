package dbuswire

import (
	"fmt"
	"net"
	"os"
	"sync"
)

// maxQueuedFDs bounds descriptors received ahead of their message.
const maxQueuedFDs = 2 * maxFDs

// fdConn reads from the bus socket and keeps the file descriptors that
// arrive with the bytes (SCM_RIGHTS, Linux) in order, so each message
// can take the ones its UNIX_FDS field announces.
type fdConn struct {
	net.Conn
	// acceptFDs is set once the bus agreed to NEGOTIATE_UNIX_FD;
	// descriptors that arrive without it are closed and fail the read.
	acceptFDs bool

	mu    sync.Mutex
	queue []*os.File
}

func (t *fdConn) push(files []*os.File) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.acceptFDs || len(t.queue)+len(files) > maxQueuedFDs {
		for _, f := range files {
			_ = f.Close()
		}
		return malformed("beklenmeyen dosya tanımlayıcısı")
	}
	t.queue = append(t.queue, files...)
	return nil
}

// takeFDs removes the next n descriptors.
func (t *fdConn) takeFDs(n int) ([]*os.File, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n > len(t.queue) {
		return nil, fmt.Errorf("%w: ileti %d tanımlayıcı bildiriyor, %d geldi", ErrMalformed, n, len(t.queue))
	}
	out := append([]*os.File(nil), t.queue[:n]...)
	t.queue = t.queue[n:]
	return out, nil
}

// closeQueued closes descriptors no message took.
func (t *fdConn) closeQueued() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, f := range t.queue {
		_ = f.Close()
	}
	t.queue = nil
}
