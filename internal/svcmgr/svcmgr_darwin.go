//go:build darwin

package svcmgr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const darwinToolTimeout = 60 * time.Second

// darwinTools are the only programs the macOS code runs, by absolute path
// on the sealed system volume (F-125).
var darwinTools = map[string]string{
	"launchctl": "/bin/launchctl",
}

func runDarwinTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	p, ok := darwinTools[name]
	if !ok {
		return nil, fmt.Errorf("araç adı geçersiz: %q", name)
	}
	ctx, cancel := context.WithTimeout(ctx, darwinToolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

func realOps() sysOps {
	return sysOps{
		run: runDarwinTool,
		executable: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(exe)
		},
		euid: os.Geteuid,
		ensureUser: func(context.Context) (int, int, error) {
			return 0, 0, errors.New("macOS'ta servis kullanıcısı oluşturulmaz")
		},
		chown:   os.Chown,
		trusted: CheckTrustedPath,
	}
}

// Install installs or updates the device launch daemon (ADR-0100).
func Install(ctx context.Context, o Options) (Result, error) {
	return installDarwin(ctx, realOps(), o)
}

// Start, Stop and Restart control the device launch daemon.
func Start(ctx context.Context, r Role) error   { return controlDarwin(ctx, realOps(), "start", r) }
func Stop(ctx context.Context, r Role) error    { return controlDarwin(ctx, realOps(), "stop", r) }
func Restart(ctx context.Context, r Role) error { return controlDarwin(ctx, realOps(), "restart", r) }

// Get returns the device launch daemon's state.
func Get(ctx context.Context, r Role) (Status, error) { return statusDarwin(ctx, realOps(), r) }

// Uninstall unloads and removes what "service install" wrote; state and
// parameters stay.
func Uninstall(ctx context.Context, r Role) ([]string, error) {
	return uninstallDarwin(ctx, realOps(), r)
}
