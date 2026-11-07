//go:build darwin

package support

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// macOS collector: ps, launchctl, the unified log (errors and faults of the
// last hour), statfs and the system LaunchAgents/LaunchDaemons folders.
// Written against the tools' documented output; not yet tried on a Mac.

type systemCollector struct{}

func (systemCollector) Processes(ctx context.Context) ([]Process, error) {
	out, err := runCommand(ctx, "ps", "-axo", "pid=,rss=,comm=")
	if err != nil {
		return nil, ErrUnsupported
	}
	var list []Process
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		rss, err2 := strconv.ParseUint(f[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		name := strings.Join(f[2:], " ")
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		list = append(list, Process{PID: pid, Name: name, MemoryKB: rss})
	}
	return list, nil
}

func (systemCollector) Services(ctx context.Context) ([]Service, error) {
	out, err := runCommand(ctx, "launchctl", "list")
	if err != nil {
		return nil, ErrUnsupported
	}
	var list []Service
	for i, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 {
			continue
		}
		state := "stopped"
		if f[0] != "-" {
			state = "running"
		}
		list = append(list, Service{Name: f[2], State: state})
	}
	return list, nil
}

func (systemCollector) Events(ctx context.Context) ([]Event, error) {
	out, err := runCommand(ctx, "log", "show", "--last", "1h", "--style", "ndjson", "--predicate", "messageType == error OR messageType == fault")
	if err != nil {
		return nil, ErrUnsupported
	}
	var list []Event
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() && len(list) < 4*MaxEvents {
		var m struct {
			Timestamp   string `json:"timestamp"`
			MessageType string `json:"messageType"`
			Process     string `json:"processImagePath"`
			Message     string `json:"eventMessage"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Message == "" {
			continue
		}
		at, _ := time.Parse("2006-01-02 15:04:05.000000-0700", m.Timestamp)
		src := m.Process
		if i := strings.LastIndexByte(src, '/'); i >= 0 {
			src = src[i+1:]
		}
		level := "error"
		if strings.EqualFold(m.MessageType, "fault") {
			level = "critical"
		}
		list = append(list, Event{Time: at.UTC(), Level: level, Source: src, Message: m.Message})
	}
	return list, nil
}

func (systemCollector) Disks(context.Context) ([]Disk, error) {
	mounts := []string{"/"}
	if entries, err := os.ReadDir("/Volumes"); err == nil {
		for _, e := range entries {
			mounts = append(mounts, "/Volumes/"+e.Name())
		}
	}
	var list []Disk
	for _, m := range mounts {
		var st syscall.Statfs_t
		if syscall.Statfs(m, &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := uint64(st.Bsize)
		list = append(list, Disk{Mount: m, TotalBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs})
	}
	return list, nil
}

func (systemCollector) Startup(context.Context) ([]StartupItem, error) {
	var list []StartupItem
	for _, dir := range []string{"/Library/LaunchAgents", "/Library/LaunchDaemons"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".plist") {
				list = append(list, StartupItem{Name: strings.TrimSuffix(e.Name(), ".plist"), Location: dir})
			}
		}
	}
	return list, nil
}

func (systemCollector) Kill(ctx context.Context, pid int, name string) error {
	if err := checkKill(pid, name); err != nil {
		return err
	}
	out, err := runCommand(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	if err != nil {
		return ErrNoProcess
	}
	got := strings.TrimSpace(string(out))
	if i := strings.LastIndexByte(got, '/'); i >= 0 {
		got = got[i+1:]
	}
	if got != name {
		return ErrNoProcess
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return ErrNoProcess
	}
	return nil
}
