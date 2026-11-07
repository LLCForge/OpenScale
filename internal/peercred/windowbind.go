package peercred

import (
	"errors"
	"fmt"
	"sync"
)

// Panel session bound to the window process (#646, ADR-0195 section 7).
// When the panel exchanges the one-time sign-in link for a session cookie,
// it records which OpenScale window process made the request: the nearest
// ancestor of the requesting process that runs an allowed OpenScale
// program (the WebView2 network process is a grandchild of
// "openscale panel-window"). Every later request with that cookie must
// come from a descendant of the same window process. A cookie copied into
// another browser, or used by a script, then fails even on the same
// computer and user.
//
// Where the system cannot name the process behind a loopback connection
// (Linux, macOS) the binding is not made and Check passes: the cookie
// rules of the panel (HttpOnly, SameSite=Strict, short lifetime) remain
// the protection there.

// ErrWindowBinding: the request does not come from the bound window.
var ErrWindowBinding = errors.New("panel session is bound to another window process")

// maxBindings bounds the table; the oldest binding is dropped.
const maxBindings = 64

// WindowBinding maps session ids to window process ids. The zero value
// is not usable; use NewWindowBinding.
type WindowBinding struct {
	programs ProgramPolicy
	mu       sync.Mutex
	bound    map[string]int
	order    []string
	// lookup and image are replaced in tests.
	lookup func(remote, local string) (int, error)
	image  func(pid int) (string, error)
	parent func(pid int) (int, error)
}

// NewWindowBinding binds to windows running one of the allowed programs.
func NewWindowBinding(programs ProgramPolicy) *WindowBinding {
	return &WindowBinding{
		programs: programs,
		bound:    map[string]int{},
		lookup:   ProcessOf,
		image:    ProcessImagePath,
		parent:   parentProcess,
	}
}

// windowOf walks up from pid to the first process running an allowed
// program; 0 when there is none or the system cannot tell.
func (b *WindowBinding) windowOf(pid int) int {
	cur := pid
	for range maxAncestry {
		if cur <= 0 {
			return 0
		}
		if path, err := b.image(cur); err == nil && b.programs.AllowsProgram(path) == nil {
			return cur
		}
		next, err := b.parent(cur)
		if err != nil || next == cur {
			return 0
		}
		cur = next
	}
	return 0
}

// Bind records the window behind the sign-in request. It returns the
// window process id, or 0 when no binding was made (unsupported system,
// or the request does not come from an OpenScale window: a browser
// sign-in stays unbound, as before).
func (b *WindowBinding) Bind(session, remote, local string) (int, error) {
	if session == "" {
		return 0, errors.New("empty session")
	}
	pid, err := b.lookup(remote, local)
	if err != nil {
		return 0, err
	}
	win := b.windowOf(pid)
	if win == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.bound[session]; !ok {
		b.order = append(b.order, session)
		if len(b.order) > maxBindings {
			delete(b.bound, b.order[0])
			b.order = b.order[1:]
		}
	}
	b.bound[session] = win
	return win, nil
}

// Check verifies a request with a bound session. An unbound session
// passes.
func (b *WindowBinding) Check(session, remote, local string) error {
	b.mu.Lock()
	win, ok := b.bound[session]
	b.mu.Unlock()
	if !ok {
		return nil
	}
	pid, err := b.lookup(remote, local)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWindowBinding, err)
	}
	cur := pid
	for range maxAncestry {
		if cur == win {
			return nil
		}
		next, err := b.parent(cur)
		if err != nil || next <= 0 || next == cur {
			break
		}
		cur = next
	}
	return fmt.Errorf("%w (pid %d, window %d)", ErrWindowBinding, pid, win)
}

// Forget drops a session (sign-out).
func (b *WindowBinding) Forget(session string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.bound[session]; !ok {
		return
	}
	delete(b.bound, session)
	for i, s := range b.order {
		if s == session {
			b.order = append(b.order[:i], b.order[i+1:]...)
			break
		}
	}
}
