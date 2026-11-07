//go:build windows

package rdesk

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procSetThreadDpiAwarenessContext = modUser32.NewProc("SetThreadDpiAwarenessContext")
)

// DPI awareness contexts (windef.h); the values are negative handles.
const (
	dpiAwarenessPerMonitorV2 = ^uintptr(3) // -4
	dpiAwarenessPerMonitor   = ^uintptr(2) // -3
)

var errClosed = errors.New("rdesk: kapatıldı")

// winThread runs GDI, input and clipboard calls on one locked OS thread
// that is per-monitor DPI aware, so coordinates are physical pixels and
// thread-affine handles (the clipboard) are used from a single thread.
// The thread is never unlocked: when the goroutine ends the runtime
// terminates it, so the changed DPI awareness never leaks to other
// goroutines.
type winThread struct {
	reqs chan func()
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

func startWinThread(init func() error, cleanup func()) (*winThread, error) {
	t := &winThread{reqs: make(chan func()), quit: make(chan struct{}), done: make(chan struct{})}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer close(t.done)
		if procSetThreadDpiAwarenessContext.Find() == nil {
			if r, _, _ := procSetThreadDpiAwarenessContext.Call(dpiAwarenessPerMonitorV2); r == 0 {
				_, _, _ = procSetThreadDpiAwarenessContext.Call(dpiAwarenessPerMonitor)
			}
		}
		if init != nil {
			if err := init(); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
		if cleanup != nil {
			defer cleanup()
		}
		for {
			select {
			case f := <-t.reqs:
				f()
			case <-t.quit:
				return
			}
		}
	}()
	if err := <-errc; err != nil {
		return nil, err
	}
	return t, nil
}

// run executes f on the thread and waits for it.
func (t *winThread) run(f func()) error {
	finished := make(chan struct{})
	select {
	case t.reqs <- func() { f(); close(finished) }:
	case <-t.done:
		return errClosed
	}
	<-finished
	return nil
}

func (t *winThread) close() {
	t.once.Do(func() { close(t.quit) })
	<-t.done
}

// ptrFromHandle turns an address returned by a system call (memory not
// owned by Go) into an unsafe.Pointer.
func ptrFromHandle(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}
