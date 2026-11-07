//go:build linux

package svcmgr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const toolTimeout = 60 * time.Second

// selfExeLink opens the image of this process whatever its path holds now.
const selfExeLink = "/proc/self/exe"

// runningProgramPath names the file to install as the root service.
//
// SECURITY FIX: CWE-367 The folder a program is started from with sudo can be
// writable by others, so the path must not be read again after the start:
// the name could hold another file by now. The kernel refuses writes to a
// running image (ETXTBSY), so what this link opens is what sudo started.
func runningProgramPath() (string, error) {
	if _, err := os.Stat(selfExeLink); err != nil {
		return "", fmt.Errorf("çalışan program okunamadı: %w", err)
	}
	return selfExeLink, nil
}

// Tools are run by absolute path with a minimal environment (F-125), so
// neither PATH nor variables left by the caller choose what runs as root.
var toolDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

func toolPath(name string) (string, error) {
	if strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("araç adı geçersiz: %q", name)
	}
	for _, d := range toolDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s bulunamadı", name)
}

func runTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	p, err := toolPath(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

func ensureUser(ctx context.Context) (int, int, error) {
	u, err := user.Lookup(serviceUser)
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return 0, 0, err
		}
		if _, err := runTool(ctx, "useradd", "--system", "--home-dir", "/var/lib/openscale", "--no-create-home",
			"--shell", "/usr/sbin/nologin", serviceUser); err != nil {
			return 0, 0, err
		}
		if u, err = user.Lookup(serviceUser); err != nil {
			return 0, 0, err
		}
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, errors.New("openscale kullanıcısının kimliği okunamadı")
	}
	return uid, gid, nil
}

func realOps() (sysOps, error) {
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return sysOps{}, fmt.Errorf("%w (systemd çalışmıyor)", ErrUnsupported)
	}
	return sysOps{
		run:        runTool,
		executable: runningProgramPath,
		euid:       os.Geteuid,
		ensureUser: ensureUser,
		chown:      os.Chown,
		trusted:    CheckTrustedPath,
	}, nil
}

// Install installs or updates the role's unit and starts it when this
// computer has joined the network.
func Install(ctx context.Context, o Options) (Result, error) {
	s, err := realOps()
	if err != nil {
		return Result{}, err
	}
	return installLinux(ctx, s, o)
}

// Start, Stop and Restart control the role's unit.
func Start(ctx context.Context, r Role) error   { return control(ctx, "start", r) }
func Stop(ctx context.Context, r Role) error    { return control(ctx, "stop", r) }
func Restart(ctx context.Context, r Role) error { return control(ctx, "restart", r) }

func control(ctx context.Context, verb string, r Role) error {
	s, err := realOps()
	if err != nil {
		return err
	}
	return controlLinux(ctx, s, verb, r)
}

// Get returns the role's unit state.
func Get(ctx context.Context, r Role) (Status, error) {
	s, err := realOps()
	if err != nil {
		return Status{}, err
	}
	return statusLinux(ctx, s, r)
}

// Uninstall stops, disables and removes what "service install" wrote;
// state and parameters stay.
func Uninstall(ctx context.Context, r Role) ([]string, error) {
	s, err := realOps()
	if err != nil {
		return nil, err
	}
	return uninstallLinux(ctx, s, r)
}
