package srvaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"
)

// Provider intervention traces (#637, ADR-0184). A VPS provider can reboot
// the machine, boot another kernel or command line, log in on the serial
// console, run commands through a guest agent or feed new cloud-init data.
// None of this can be prevented from inside the guest, but most of it leaves
// traces that the guest can read after the fact. ProviderTraces compares
// the current boot with the previous one (a small state file) and reports
// what changed. It only reads; a provider with full control can of course
// also hide traces, so a clean result is no proof (ADR-0109).

// BootState is what is remembered between checks.
type BootState struct {
	Schema        int       `json:"schema"`
	BootID        string    `json:"boot_id"`
	Kernel        string    `json:"kernel"`
	CmdlineSHA256 string    `json:"cmdline_sha256"`
	InstanceID    string    `json:"instance_id,omitempty"`
	ConsoleLogins []string  `json:"console_logins,omitempty"` // "line user unix-seconds"
	CheckedAt     time.Time `json:"checked_at"`
}

// ProviderEvent is one finding.
type ProviderEvent struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // "info", "warning", "critical"
	Message  string `json:"message"`
}

// Event kinds.
const (
	EventReboot         = "reboot"
	EventKernelChanged  = "kernel-changed"
	EventCmdlineChanged = "cmdline-changed"
	EventConsoleLogin   = "console-login"
	EventGuestAgent     = "guest-agent"
	EventSerialGetty    = "serial-getty"
	EventCloudInit      = "cloud-init-instance"
	EventFirstCheck     = "first-check"
)

// maxStateFile bounds the state file.
const maxStateFile = 64 << 10

// ParseBootState strictly decodes a state file.
func ParseBootState(data []byte) (*BootState, error) {
	if len(data) > maxStateFile {
		return nil, errors.New("boot state too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s BootState
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("boot state: %w", err)
	}
	if s.Schema != 1 {
		return nil, fmt.Errorf("unsupported boot state schema %d", s.Schema)
	}
	return &s, nil
}

// CurrentBoot reads the current boot's facts.
func CurrentBoot(fsys fs.FS, now time.Time) BootState {
	s := BootState{Schema: 1, CheckedAt: now.UTC()}
	if v, err := readSmall(fsys, "proc/sys/kernel/random/boot_id"); err == nil {
		s.BootID = strings.TrimSpace(v)
	}
	if v, err := readSmall(fsys, "proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(v)
	}
	if v, err := readSmall(fsys, "proc/cmdline"); err == nil {
		// The digest only: the command line may carry secrets.
		sum := sha256.Sum256([]byte(strings.TrimSpace(v)))
		s.CmdlineSHA256 = hex.EncodeToString(sum[:])
	}
	if v, err := readSmall(fsys, "var/lib/cloud/data/instance-id"); err == nil {
		s.InstanceID = strings.TrimSpace(v)
	}
	s.ConsoleLogins = consoleLogins(fsys)
	return s
}

// ProviderTraces compares cur with prev (nil on the first check) and reports
// the traces. Static risks (guest agent, serial getty) are reported every
// time.
func ProviderTraces(fsys fs.FS, prev *BootState, cur BootState) []ProviderEvent {
	var ev []ProviderEvent
	if prev == nil {
		ev = append(ev, ProviderEvent{Kind: EventFirstCheck, Severity: "info", Message: "İlk denetim: bu açılış kaydedildi; sonraki denetimler değişiklikleri raporlar."})
	} else {
		if prev.BootID != "" && cur.BootID != "" && prev.BootID != cur.BootID {
			ev = append(ev, ProviderEvent{Kind: EventReboot, Severity: "warning", Message: fmt.Sprintf("Sunucu %s tarihindeki denetimden sonra yeniden başlatıldı. Siz başlatmadıysanız sağlayıcı müdahalesi olabilir.", prev.CheckedAt.Format("2006-01-02 15:04"))})
		}
		if prev.Kernel != "" && cur.Kernel != "" && prev.Kernel != cur.Kernel {
			ev = append(ev, ProviderEvent{Kind: EventKernelChanged, Severity: "warning", Message: "Çekirdek değişti: " + prev.Kernel + " -> " + cur.Kernel + ". Güncelleme yapmadıysanız sağlayıcı başka bir çekirdekle açmış olabilir."})
		}
		if prev.CmdlineSHA256 != "" && cur.CmdlineSHA256 != "" && prev.CmdlineSHA256 != cur.CmdlineSHA256 {
			ev = append(ev, ProviderEvent{Kind: EventCmdlineChanged, Severity: "critical", Message: "Çekirdek komut satırı değişti (ör. init=/bin/sh veya tek kullanıcı kipi). Sağlayıcı konsoldan müdahale etmiş olabilir."})
		}
		if prev.InstanceID != "" && cur.InstanceID != "" && prev.InstanceID != cur.InstanceID {
			ev = append(ev, ProviderEvent{Kind: EventCloudInit, Severity: "critical", Message: "cloud-init örnek kimliği değişti: sağlayıcı yeni user-data çalıştırmış (anahtar ekleme, parola sıfırlama) olabilir."})
		}
		for _, l := range cur.ConsoleLogins {
			if !slices.Contains(prev.ConsoleLogins, l) {
				ev = append(ev, ProviderEvent{Kind: EventConsoleLogin, Severity: "critical", Message: "Konsoldan oturum açıldı: " + l + ". Siz açmadıysanız sağlayıcı veya konsol erişimi olan biri girmiş olabilir."})
			}
		}
	}
	if guestAgentEnabled(fsys) {
		ev = append(ev, ProviderEvent{Kind: EventGuestAgent, Severity: "warning", Message: "QEMU misafir ajanı etkin: sağlayıcı sunucuda komut çalıştırabilir, dosya okuyup yazabilir. Gerekmiyorsa: systemctl disable --now qemu-guest-agent"})
	}
	if g := serialGettys(fsys); len(g) > 0 {
		ev = append(ev, ProviderEvent{Kind: EventSerialGetty, Severity: "info", Message: "Seri konsolda oturum açma istemi var (" + strings.Join(g, ", ") + "); sağlayıcı konsolu buradan girilebilir. Güçlü root parolası veya kilitli root kullanın."})
	}
	return ev
}

func guestAgentEnabled(fsys fs.FS) bool {
	for _, d := range []string{"etc/systemd/system/multi-user.target.wants", "etc/systemd/system/sysinit.target.wants", "etc/systemd/system/dev-virtio\\x2dports-org.qemu.guest_agent.0.device.wants"} {
		for _, u := range []string{"qemu-guest-agent.service", "qemu-ga.service"} {
			if exists(fsys, d+"/"+u) {
				return true
			}
		}
	}
	return exists(fsys, "run/qemu-ga.pid") || exists(fsys, "var/run/qemu-ga.pid")
}

func serialGettys(fsys fs.FS) []string {
	var out []string
	entries, err := fs.ReadDir(fsys, "etc/systemd/system/getty.target.wants")
	if err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "serial-getty@") {
				out = append(out, strings.TrimSuffix(strings.TrimPrefix(e.Name(), "serial-getty@"), ".service"))
			}
		}
	}
	if cmd, err := readSmall(fsys, "proc/cmdline"); err == nil {
		for _, f := range strings.Fields(cmd) {
			if v, ok := strings.CutPrefix(f, "console="); ok && (strings.HasPrefix(v, "ttyS") || strings.HasPrefix(v, "hvc") || strings.HasPrefix(v, "ttyAMA")) {
				name := strings.SplitN(v, ",", 2)[0]
				if !slices.Contains(out, name) {
					out = append(out, name)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// utmp record layout of glibc on 64-bit Linux (struct utmp, 384 bytes).
const (
	utmpSize     = 384
	utmpUserProc = 7
	utmpLineOff  = 8
	utmpLineLen  = 32
	utmpUserOff  = 44
	utmpUserLen  = 32
	utmpTimeOff  = 340
)

// consoleLogins lists user sessions on console lines (serial, hypervisor
// and the local virtual consoles) from wtmp, so past ones are seen too.
func consoleLogins(fsys fs.FS) []string {
	var out []string
	for _, p := range []string{"var/log/wtmp", "var/run/utmp", "run/utmp"} {
		data, err := readSmallLimit(fsys, p, 8<<20)
		if err != nil {
			continue
		}
		out = append(out, parseConsoleLogins(data)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func parseConsoleLogins(data []byte) []string {
	var out []string
	for off := 0; off+utmpSize <= len(data); off += utmpSize {
		r := data[off : off+utmpSize]
		if binary.LittleEndian.Uint16(r[0:2]) != utmpUserProc { // ut_type is a short
			continue
		}
		line := cstr(r[utmpLineOff : utmpLineOff+utmpLineLen])
		if !consoleLine(line) {
			continue
		}
		user := cstr(r[utmpUserOff : utmpUserOff+utmpUserLen])
		sec := binary.LittleEndian.Uint32(r[utmpTimeOff : utmpTimeOff+4])
		out = append(out, fmt.Sprintf("%s %s %d", line, user, sec))
	}
	return out
}

func consoleLine(line string) bool {
	if line == "console" {
		return true
	}
	for _, p := range []string{"ttyS", "hvc", "ttyAMA", "xvc"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	// tty1-tty63 are the virtual consoles, reachable through the provider's
	// web console (VNC); pts/* are SSH sessions.
	return strings.HasPrefix(line, "tty") && len(line) > 3 && line[3] >= '1' && line[3] <= '9'
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// readSmallLimit reads a file of at most limit bytes.
func readSmallLimit(fsys fs.FS, name string, limit int64) ([]byte, error) {
	st, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	if st.Size() > limit {
		// Large wtmp: only the newest records matter; read the whole file
		// would cost memory, so skip it with a clear limit.
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return fs.ReadFile(fsys, name)
}
