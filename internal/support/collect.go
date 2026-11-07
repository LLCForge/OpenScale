package support

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Collector reads the device's state. System returns the one for this
// operating system; tests pass their own.
type Collector interface {
	Processes(ctx context.Context) ([]Process, error)
	Services(ctx context.Context) ([]Service, error)
	Events(ctx context.Context) ([]Event, error)
	Disks(ctx context.Context) ([]Disk, error)
	Startup(ctx context.Context) ([]StartupItem, error)
	// Kill ends process pid if it still carries name (so a reused pid is
	// never hit) and is not protected.
	Kill(ctx context.Context, pid int, name string) error
}

// Collect runs the collector for one kind and returns a cleaned snapshot.
func Collect(ctx context.Context, c Collector, kind string, now time.Time) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	s := Snapshot{Kind: kind, CollectedAt: now.UTC().Truncate(time.Second)}
	var err error
	switch kind {
	case KindProcesses:
		s.Processes, err = c.Processes(ctx)
		sort.SliceStable(s.Processes, func(i, j int) bool { return s.Processes[i].MemoryKB > s.Processes[j].MemoryKB })
	case KindServices:
		s.Services, err = c.Services(ctx)
		sort.SliceStable(s.Services, func(i, j int) bool { return strings.ToLower(s.Services[i].Name) < strings.ToLower(s.Services[j].Name) })
	case KindEvents:
		s.Events, err = c.Events(ctx)
		sort.SliceStable(s.Events, func(i, j int) bool { return s.Events[i].Time.After(s.Events[j].Time) })
	case KindDisks:
		s.Disks, err = c.Disks(ctx)
	case KindStartup:
		s.Startup, err = c.Startup(ctx)
	default:
		return Snapshot{}, fmt.Errorf("bilinmeyen tür %q", kind)
	}
	if err != nil {
		return Snapshot{}, err
	}
	s.Clean()
	return s, nil
}

// System returns the collector of this operating system.
func System() Collector { return systemCollector{} }

// protectedNames are processes ending which would crash or lock the system
// or cut the support session itself. Compared case-insensitively.
var protectedNames = map[string]bool{
	"system": true, "system idle process": true, "registry": true, "smss.exe": true, "csrss.exe": true,
	"wininit.exe": true, "winlogon.exe": true, "services.exe": true, "lsass.exe": true, "lsaiso.exe": true,
	"svchost.exe": true, "fontdrvhost.exe": true, "dwm.exe": true, "memory compression": true,
	"openscale.exe": true, "openscale": true, "openscale-service": true,
	"init": true, "systemd": true, "kthreadd": true, "launchd": true, "kernel_task": true, "loginwindow": true, "windowserver": true,
}

// checkKill refuses protected processes, this process and its parent.
func checkKill(pid int, name string) error {
	switch {
	case pid <= 4 || name == "":
		return ErrProtected
	case pid == os.Getpid() || pid == os.Getppid():
		return ErrProtected
	case protectedNames[strings.ToLower(strings.TrimSpace(name))]:
		return ErrProtected
	}
	return nil
}

// runCommand runs a system tool with a bounded output and no shell. The
// environment is the service's own; LC_ALL=C keeps tools' output in a
// stable language where it matters.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: maxCommandOut}
	cmd.Stderr = io.Discard
	// Some tools exit non-zero with useful output (journalctl without
	// matches, sc with stopped services); only no output at all fails.
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s çalıştırılamadı: %w", name, err)
	}
	return out.Bytes(), nil
}

// limitWriter keeps the first n bytes and drops the rest.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	k := min(len(p), l.n)
	l.n -= k
	if _, err := l.w.Write(p[:k]); err != nil {
		return 0, err
	}
	return len(p), nil
}
