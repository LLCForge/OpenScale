//go:build windows

package support

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows collector: tasklist for processes (it reports memory without
// opening every process), the service control manager for services,
// wevtutil for the System and Application logs, the volume API for disks
// and the machine-wide Run keys and Startup folder for startup programs.
// Per-user Run keys are not read: they live under the users' SIDs.

type systemCollector struct{}

func (systemCollector) Processes(ctx context.Context) ([]Process, error) {
	out, err := runCommand(ctx, "tasklist.exe", "/fo", "csv", "/nh")
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1
	var list []Process
	for len(list) < MaxProcesses+1 {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(rec) < 5 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil {
			continue
		}
		list = append(list, Process{PID: pid, Name: rec[0], MemoryKB: digits(rec[4])})
	}
	return list, nil
}

// digits reads the number in "12.345 K" or "12,345 K" (localized).
func digits(s string) uint64 {
	var n uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			if n > (1<<63)/10 {
				return n
			}
			n = n*10 + uint64(c-'0')
		}
	}
	return n
}

var serviceStates = map[uint32]string{
	windows.SERVICE_STOPPED: "stopped", windows.SERVICE_START_PENDING: "starting", windows.SERVICE_STOP_PENDING: "stopping",
	windows.SERVICE_RUNNING: "running", windows.SERVICE_CONTINUE_PENDING: "continuing", windows.SERVICE_PAUSE_PENDING: "pausing",
	windows.SERVICE_PAUSED: "paused",
}

func (systemCollector) Services(ctx context.Context) ([]Service, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(m)
	var needed, count, resume uint32
	buf := make([]byte, 64<<10)
	var list []Service
	for attempt := 0; attempt < 32 && ctx.Err() == nil; attempt++ {
		err := windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		if count > 0 {
			entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
			for _, e := range entries {
				state := serviceStates[e.ServiceStatusProcess.CurrentState]
				if state == "" {
					state = "unknown"
				}
				list = append(list, Service{Name: windows.UTF16PtrToString(e.ServiceName), Display: windows.UTF16PtrToString(e.DisplayName), State: state})
			}
		}
		if err == nil || len(list) > MaxServices {
			break
		}
		if needed > uint32(len(buf)) && needed < 4<<20 {
			buf = make([]byte, needed)
		}
	}
	return list, nil
}

// Events from wevtutil's rendered XML; message texts come in the system's
// language.
type winEvents struct {
	Events []winEvent `xml:"Event"`
}

type winEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Rendering struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

var winLevels = map[int]string{1: "critical", 2: "error", 3: "warning"}

func (systemCollector) Events(ctx context.Context) ([]Event, error) {
	var list []Event
	var firstErr error
	for _, log := range []string{"System", "Application"} {
		// English messages keep the text mostly ASCII; wevtutil writes in
		// the console code page, so bytes that are not UTF-8 are replaced
		// before XML decoding.
		out, err := runCommand(ctx, "wevtutil.exe", "qe", log, "/c:60", "/rd:true", "/l:en-US", "/f:RenderedXml", "/q:*[System[(Level=1 or Level=2 or Level=3)]]")
		if err != nil {
			firstErr = cmpErr(firstErr, err)
			continue
		}
		var evs winEvents
		data := []byte("<Events>" + strings.ToValidUTF8(string(out), "?") + "</Events>")
		if err := xml.Unmarshal(data, &evs); err != nil {
			firstErr = cmpErr(firstErr, err)
			continue
		}
		for _, e := range evs.Events {
			at, _ := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
			level := winLevels[e.System.Level]
			if level == "" {
				level = "info"
			}
			list = append(list, Event{Time: at.UTC(), Level: level, Source: log + "/" + e.System.Provider.Name, ID: e.System.EventID, Message: e.Rendering.Message})
		}
	}
	if len(list) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return list, nil
}

func cmpErr(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

func (systemCollector) Disks(context.Context) ([]Disk, error) {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil {
		return nil, err
	}
	var list []Disk
	for _, root := range strings.Split(windows.UTF16ToString(buf[:n]), "\x00") {
		if root == "" {
			continue
		}
		p, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
			continue
		}
		list = append(list, Disk{Mount: root, TotalBytes: total, FreeBytes: totalFree})
	}
	return list, nil
}

func (systemCollector) Startup(ctx context.Context) ([]StartupItem, error) {
	var list []StartupItem
	for _, key := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	} {
		out, err := runCommand(ctx, "reg.exe", "query", key)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimRight(line, "\r")
			if !strings.HasPrefix(line, "    ") {
				continue
			}
			fields := strings.SplitN(strings.TrimSpace(line), "    ", 3)
			if len(fields) < 3 || !strings.HasPrefix(fields[1], "REG_") {
				continue
			}
			list = append(list, StartupItem{Name: fields[0], Location: key, Command: strings.TrimSpace(fields[2])})
		}
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		dir := filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && !strings.EqualFold(e.Name(), "desktop.ini") {
					list = append(list, StartupItem{Name: e.Name(), Location: "Startup klasörü (tüm kullanıcılar)"})
				}
			}
		}
	}
	return list, nil
}

func (systemCollector) Kill(_ context.Context, pid int, name string) error {
	if err := checkKill(pid, name); err != nil {
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ErrNoProcess
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ErrNoProcess
	}
	// The open handle pins the process: the name checked is the name of
	// the process that gets terminated.
	if !strings.EqualFold(filepath.Base(windows.UTF16ToString(buf[:size])), name) {
		return ErrNoProcess
	}
	return windows.TerminateProcess(h, 1)
}
