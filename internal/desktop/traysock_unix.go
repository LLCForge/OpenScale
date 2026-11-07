//go:build darwin || linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/service"
)

// The tray socket shared by macOS (ADR-0227) and Linux (ADR-0234): the
// app runs as the signed-in user, the service as root; the service
// listens on TraySocket in a root-owned folder, asks the kernel who
// connected and forwards a fixed list of tray requests (traygate.go).

func ownExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// newGatewayClient talks to the service through the tray socket.
func newGatewayClient() *trayClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", TraySocket)
		},
		MaxIdleConns:       4,
		IdleConnTimeout:    60 * time.Second,
		DisableCompression: true,
	}
	return &trayClient{
		base:    gateBase,
		gateway: true,
		http: &http.Client{
			Transport:     tr,
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// serveTrayGate listens on the tray socket until ctx ends.
func serveTrayGate(ctx context.Context, logger *slog.Logger, dataDir string) error {
	exe, err := ownExecutable()
	if err != nil {
		return err
	}
	var hashes programHashes
	want, err := hashes.sum(exe)
	if err != nil {
		return fmt.Errorf("own program: %w", err)
	}
	ln, err := listenTraySocket()
	if err != nil {
		return err
	}
	policy := trayGatePolicy()
	policy.want, policy.hash = want, hashes.sum
	gl := &gateListener{Listener: ln, policy: policy, logger: logger, slots: make(chan struct{}, maxGateConns)}
	srv := &http.Server{
		Handler:           newTrayGate(panelBase, func() (string, error) { return service.ReadToken(dataDir) }, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      gateUpstreamTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	err = srv.Serve(gl)
	_ = os.Remove(TraySocket)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// userInGroup asks the directory service (os/user; getgrouplist in a cgo
// build) whether uid belongs to gid.
func userInGroup(uid, gid int) bool {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false
	}
	return slices.Contains(ids, strconv.Itoa(gid))
}

// listenTraySocket creates the socket in a root-owned folder that no one
// else can write, replacing a stale socket from an earlier run. The
// socket itself is open to every local user (0666): the kernel tells the
// service who connected and gateListener decides.
func listenTraySocket() (net.Listener, error) {
	if err := os.MkdirAll(traySocketDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(traySocketDir, 0o755); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(traySocketDir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || st.Uid != 0 {
		return nil, fmt.Errorf("%s root'a ait bir klasör değil", traySocketDir)
	}
	if fi, err := os.Lstat(TraySocket); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s bir soket değil; elle kaldırın", TraySocket)
		}
		if err := os.Remove(TraySocket); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", TraySocket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(TraySocket, 0o666); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// gateListener accepts only callers the policy allows and at most
// cap(slots) at a time; refused connections are closed at once.
type gateListener struct {
	net.Listener
	policy gatePeerPolicy
	logger *slog.Logger
	slots  chan struct{}
}

func (l *gateListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			_ = c.Close()
			continue
		}
		id, err := peercred.UnixPeer(uc)
		if err == nil {
			err = l.policy.check(id)
		}
		if err != nil {
			l.logger.Warn("tray socket: caller refused", "pid", id.PID, "uid", id.UID, "error", err.Error())
			_ = c.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
		default:
			l.logger.Warn("tray socket: too many connections")
			_ = c.Close()
			continue
		}
		return &slotConn{Conn: c, release: func() { <-l.slots }}, nil
	}
}

// slotConn gives its slot back once when closed.
type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
