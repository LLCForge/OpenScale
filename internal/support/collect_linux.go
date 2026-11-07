//go:build linux

package support

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Linux collector: /proc for processes, systemctl for services and enabled
// units, journalctl for warnings and errors, statfs for disks and
// /etc/xdg/autostart for desktop autostart entries.

type systemCollector struct{}

func (systemCollector) Processes(ctx context.Context) ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, ErrUnsupported
	}
	var list []Process
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		name, rss, ok := procStatus(pid)
		if !ok {
			continue
		}
		list = append(list, Process{PID: pid, Name: name, MemoryKB: rss})
		if len(list) > MaxProcesses {
			break
		}
	}
	return list, nil
}

// procStatus reads Name and VmRSS (kB) of /proc/<pid>/status.
func procStatus(pid int) (string, uint64, bool) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	var name string
	var rss uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			name = v
		case "VmRSS":
			n, _ := strconv.ParseUint(strings.TrimSuffix(v, " kB"), 10, 64)
			rss = n
		}
	}
	return name, rss, name != ""
}

func (systemCollector) Services(ctx context.Context) ([]Service, error) {
	out, err := runCommand(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, ErrUnsupported
	}
	var list []Service
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		list = append(list, Service{Name: strings.TrimSuffix(f[0], ".service"), State: f[2] + "/" + f[3], Display: strings.Join(f[4:], " ")})
	}
	return list, nil
}

var journalLevels = map[string]string{"0": "critical", "1": "critical", "2": "critical", "3": "error", "4": "warning"}

func (systemCollector) Events(ctx context.Context) ([]Event, error) {
	out, err := runCommand(ctx, "journalctl", "-p", "warning", "-n", strconv.Itoa(MaxEvents), "-o", "json", "--no-pager", "-q")
	if err != nil {
		return nil, ErrUnsupported
	}
	var list []Event
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var m map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		ev := Event{Level: journalLevels[jsonString(m["PRIORITY"])], Source: jsonString(m["SYSLOG_IDENTIFIER"]), Message: jsonString(m["MESSAGE"])}
		if ev.Source == "" {
			ev.Source = jsonString(m["_COMM"])
		}
		if us, err := strconv.ParseInt(jsonString(m["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
			ev.Time = time.UnixMicro(us).UTC()
		}
		if ev.Level == "" {
			ev.Level = "warning"
		}
		list = append(list, ev)
	}
	return list, nil
}

// jsonString reads a journal field: a string, or an array of bytes for
// binary messages.
func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	if json.Unmarshal(raw, &b) == nil {
		return string(b)
	}
	return ""
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "jfs": true, "reiserfs": true, "bcachefs": true}

func (systemCollector) Disks(context.Context) ([]Disk, error) {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil, ErrUnsupported
	}
	seen := map[string]bool{}
	var list []Disk
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		mount := strings.ReplaceAll(f[1], `\040`, " ")
		var st syscall.Statfs_t
		if syscall.Statfs(mount, &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := uint64(st.Bsize)
		list = append(list, Disk{Mount: mount, TotalBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs})
	}
	return list, nil
}

func (systemCollector) Startup(ctx context.Context) ([]StartupItem, error) {
	var list []StartupItem
	if out, err := runCommand(ctx, "systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) >= 1 {
				list = append(list, StartupItem{Name: strings.TrimSuffix(f[0], ".service"), Location: "systemd"})
			}
		}
	}
	if entries, err := os.ReadDir("/etc/xdg/autostart"); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".desktop") {
				list = append(list, StartupItem{Name: strings.TrimSuffix(e.Name(), ".desktop"), Location: "/etc/xdg/autostart"})
			}
		}
	}
	return list, nil
}

func (systemCollector) Kill(_ context.Context, pid int, name string) error {
	if err := checkKill(pid, name); err != nil {
		return err
	}
	// Kernel threads have no executable and are never ended.
	if _, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err != nil {
		return ErrNoProcess
	}
	got, _, ok := procStatus(pid)
	if !ok || got != name {
		return ErrNoProcess
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return ErrNoProcess
	}
	return nil
}
