//go:build darwin || linux

package desktop

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/openscale/openscale/internal/peercred"
)

// One tray or menu bar app per user (macOS ADR-0227, Linux ADR-0234).
// The first instance holds an exclusive lock on menubar.lock in the
// user's OpenScale folder (0700) and listens on menubar.sock beside it; a
// later start (Finder, Spotlight, the launch agent, XDG autostart) asks
// it to open the panel and exits, like the Windows tray
// (askRunningTrayToOpen). Only the same user may ask (LOCAL_PEERCRED,
// SO_PEERCRED).

const (
	instanceLock   = "menubar.lock"
	instanceSocket = "menubar.sock"
	instanceMsg    = "open"
)

// errOtherInstance: another menu bar app of this user runs.
var errOtherInstance = errors.New("OpenScale tepsi uygulaması zaten çalışıyor")

// claimInstance makes this process the user's menu bar app. When another
// one runs it is asked to open the panel (unless quiet) and
// errOtherInstance is returned. onOpen runs for each later start.
func claimInstance(ctx context.Context, dir string, quiet bool, onOpen func()) (release func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, instanceLock)
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, instanceSocket)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if !quiet {
			askInstanceToOpen(sock)
		}
		return nil, errOtherInstance
	}
	if len(sock) >= maxSunPath {
		// The lock alone still keeps one instance; later starts just exit.
		return func() { _ = f.Close() }, nil
	}
	if fi, err := os.Lstat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(sock)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return func() { _ = f.Close() }, nil
	}
	_ = os.Chmod(sock, 0o600)
	go serveInstance(ctx, ln, onOpen)
	return func() {
		_ = ln.Close()
		_ = os.Remove(sock)
		_ = f.Close()
	}, nil
}

func serveInstance(ctx context.Context, ln net.Listener, onOpen func()) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	self := os.Geteuid()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			uc, ok := c.(*net.UnixConn)
			if !ok {
				return
			}
			id, err := peercred.UnixPeer(uc)
			if err != nil || id.UID != self {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, err := bufio.NewReader(c).ReadString('\n')
			if err == nil && line == instanceMsg+"\n" {
				onOpen()
			}
		}(c)
	}
}

func askInstanceToOpen(sock string) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte(instanceMsg + "\n"))
}
