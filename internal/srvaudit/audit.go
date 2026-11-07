// Package srvaudit checks a coordinator or exit node server (#478) and
// probes its public surface from outside (#479). The audit only reads
// files and the kernel's socket tables; it never changes the system, runs
// no package manager and sends nothing anywhere. The surface probe sends a
// handful of datagrams and TCP connection attempts to the address the
// owner names, nothing else.
//
// The results are advice for the owner, never proof: a modified server can
// show any file contents (ADR-0109).
package srvaudit

import (
	"fmt"
	"io/fs"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/posture"
)

// Status of one check.
type Status string

const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

// Label is the Turkish display form.
func (s Status) Label() string {
	switch s {
	case Pass:
		return "TAMAM"
	case Warn:
		return "UYARI"
	case Fail:
		return "SORUN"
	}
	return "BİLİNMİYOR"
}

// Check is one audited item.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Report is the audit result. Score is 0-100 over the checks that could
// run; unknown checks are left out of both sides.
type Report struct {
	Schema int     `json:"schema"`
	Role   string  `json:"role"`
	Score  int     `json:"score"`
	Checks []Check `json:"checks"`
}

// Roles.
const (
	RoleCoordinator = "coordinator"
	RoleExit        = "exit"
)

// Options of an audit.
type Options struct {
	Role string
	// ExpectUDP and ExpectTCP are the ports that may listen on a public
	// address. Zero values use the role's defaults (see Defaults).
	ExpectUDP, ExpectTCP []uint16
}

// Facts are the values read outside the file system (tests set them).
type Facts struct {
	DiskEncryption posture.State
	Firewall       posture.State
	// Listeners are the sockets bound to a non-loopback address; nil
	// means the socket tables could not be read.
	Listeners []Listener
}

// Defaults fills in the role's expected ports: the WireGuard UDP port and
// SSH; for a coordinator also the TCP transport port from its
// environment file (ADR-0032).
func Defaults(fsys fs.FS, o Options) Options {
	if o.Role == "" {
		o.Role = RoleCoordinator
	}
	if len(o.ExpectUDP) == 0 {
		if o.Role == RoleExit {
			o.ExpectUDP = []uint16{41821}
		} else {
			o.ExpectUDP = []uint16{41820}
		}
	}
	if len(o.ExpectTCP) == 0 {
		o.ExpectTCP = []uint16{22}
		if o.Role == RoleCoordinator {
			if p := tcpTransportPort(fsys); p != 0 {
				o.ExpectTCP = append(o.ExpectTCP, p)
			}
		}
	}
	return o
}

// tcpTransportPort reads OPENSCALE_TCP_LISTEN from the coordinator's
// environment file.
func tcpTransportPort(fsys fs.FS) uint16 {
	data, err := readSmall(fsys, "etc/default/openscale-coordinator")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(data, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) != "OPENSCALE_TCP_LISTEN" {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if i := strings.LastIndexByte(v, ':'); i >= 0 {
			v = v[i+1:]
		}
		if n, err := strconv.ParseUint(v, 10, 16); err == nil && n > 0 {
			return uint16(n)
		}
	}
	return 0
}

// Run audits the system rooted at fsys (os.DirFS("/") on a server).
func Run(fsys fs.FS, facts Facts, o Options) Report {
	o = Defaults(fsys, o)
	sshd := readSSHD(fsys)
	checks := []Check{
		checkSSHPassword(sshd),
		checkSSHRoot(sshd),
		checkPorts(facts.Listeners, o),
		checkUpdates(fsys),
		checkState("disk", "Disk şifreleme", 10, facts.DiskEncryption,
			"Kök dosya sistemi şifreli (LUKS).", "Kök dosya sistemi şifreli görünmüyor; koordinatör anahtarı diskte açık durur.",
			"Yeni kurulumda LUKS ile şifreli disk seçin (ADR-0109)."),
		checkTimeSync(fsys),
		checkState("firewall", "Güvenlik duvarı", 10, facts.Firewall,
			"Gelen trafik süzülüyor (nftables/ufw).", "Gelen trafiği süzen bir güvenlik duvarı bulunamadı.",
			"deploy/linux/nftables.conf dosyasını /etc/nftables.conf olarak kurun (docs/sunucu-kurulumu.md)."),
		checkUnit(fsys, o.Role),
	}
	checks = append(checks, g2Checks(fsys, o)...) // ADR-0184 (g2_checks.go)
	return Report{Schema: 1, Role: o.Role, Score: score(checks), Checks: checks}
}

func score(checks []Check) int {
	got, max := 0.0, 0
	for _, c := range checks {
		switch c.Status {
		case Pass:
			got += float64(c.Weight)
		case Warn:
			got += float64(c.Weight) / 2
		case Unknown:
			continue
		}
		max += c.Weight
	}
	if max == 0 {
		return 0
	}
	return int(math.Round(100 * got / float64(max)))
}

func checkState(id, title string, weight int, s posture.State, on, off, fix string) Check {
	c := Check{ID: id, Title: title, Weight: weight}
	switch s {
	case posture.On:
		c.Status, c.Detail = Pass, on
	case posture.Off:
		c.Status, c.Detail, c.Fix = Fail, off, fix
	default:
		c.Status, c.Detail = Unknown, "Denetlenemedi (root olarak çalıştırın; nft veya cryptsetup bilgisi okunamadı)."
	}
	return c
}

func checkSSHPassword(s *sshdConfig) Check {
	c := Check{ID: "ssh-password", Title: "SSH parola girişi", Weight: 20}
	if s == nil {
		c.Status, c.Detail = Pass, "SSH sunucusu kurulu değil."
		return c
	}
	pw := strings.ToLower(s.get("passwordauthentication", "yes"))
	kbd := strings.ToLower(s.get("kbdinteractiveauthentication", s.get("challengeresponseauthentication", "yes")))
	usePAM := strings.ToLower(s.get("usepam", "no"))
	switch {
	case pw != "no":
		c.Status, c.Detail = Fail, "PasswordAuthentication açık: parola tahmini saldırılarına açık."
	case kbd != "no" && usePAM == "yes":
		c.Status, c.Detail = Warn, "Parola kapalı ama klavye etkileşimli giriş (PAM) açık; PAM parola sorabilir."
	default:
		c.Status, c.Detail = Pass, "Yalnızca anahtarla giriş."
		return c
	}
	c.Fix = "deploy/linux/sshd-openscale.conf dosyasını /etc/ssh/sshd_config.d/10-openscale.conf olarak kurun ve sshd'yi yeniden yükleyin."
	return c
}

func checkSSHRoot(s *sshdConfig) Check {
	c := Check{ID: "ssh-root", Title: "SSH root girişi", Weight: 15}
	if s == nil {
		c.Status, c.Detail = Pass, "SSH sunucusu kurulu değil."
		return c
	}
	switch v := strings.ToLower(s.get("permitrootlogin", "prohibit-password")); v {
	case "no":
		c.Status, c.Detail = Pass, "root ile giriş kapalı."
	case "prohibit-password", "without-password", "forced-commands-only":
		// The shipped sshd-openscale.conf: root with a key only.
		c.Status, c.Detail = Pass, "root yalnızca anahtarla girebilir ("+v+"); ayrı bir kullanıcı ve sudo ile 'no' daha da iyidir."
	default:
		c.Status, c.Detail, c.Fix = Fail, "root parolayla girebilir (PermitRootLogin "+v+").", "PermitRootLogin no"
	}
	return c
}

func checkPorts(ls []Listener, o Options) Check {
	c := Check{ID: "ports", Title: "Açık portlar", Weight: 15}
	if ls == nil {
		c.Status, c.Detail = Unknown, "Soket tabloları okunamadı."
		return c
	}
	var extra []string
	for _, l := range ls {
		want := o.ExpectTCP
		if l.Proto == "udp" {
			want = o.ExpectUDP
		}
		if slices.Contains(want, l.Port) {
			continue
		}
		extra = append(extra, fmt.Sprintf("%d/%s", l.Port, l.Proto))
	}
	slices.Sort(extra)
	extra = slices.Compact(extra)
	if len(extra) == 0 {
		c.Status, c.Detail = Pass, "Dışarıya yalnızca beklenen portlar açık."
		return c
	}
	c.Status = Warn
	if len(extra) > 3 {
		c.Status = Fail
	}
	c.Detail = "Beklenmeyen dinleyen portlar: " + strings.Join(extra, ", ")
	c.Fix = "Gerekmeyen servisleri kapatın veya yalnızca 127.0.0.1'e bağlayın; güvenlik duvarında yalnızca WireGuard portunu açın. Beklenen bir portsa --expect-tcp/--expect-udp ile belirtin."
	return c
}

func checkUpdates(fsys fs.FS) Check {
	c := Check{ID: "updates", Title: "Otomatik güvenlik güncellemeleri", Weight: 15}
	switch {
	case exists(fsys, "usr/bin/apt-get"):
		if !exists(fsys, "usr/bin/unattended-upgrade") {
			c.Status, c.Detail = Fail, "unattended-upgrades kurulu değil."
			c.Fix = "apt install unattended-upgrades; deploy/linux/50-openscale-upgrades.conf dosyasını kurun."
			return c
		}
		if aptPeriodicEnabled(fsys) {
			c.Status, c.Detail = Pass, "unattended-upgrades etkin."
			return c
		}
		c.Status, c.Detail = Warn, "unattended-upgrades kurulu ama APT::Periodic::Unattended-Upgrade \"1\" ayarı yok."
		c.Fix = "dpkg-reconfigure -plow unattended-upgrades"
	case exists(fsys, "usr/bin/dnf") || exists(fsys, "usr/bin/dnf5"):
		for _, t := range []string{"dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"} {
			if exists(fsys, "etc/systemd/system/timers.target.wants/"+t) {
				c.Status, c.Detail = Pass, t+" etkin."
				return c
			}
		}
		c.Status, c.Detail = Fail, "dnf-automatic zamanlayıcısı etkin değil."
		c.Fix = "dnf install dnf-automatic; systemctl enable --now dnf-automatic-install.timer"
	default:
		c.Status, c.Detail = Unknown, "Paket yöneticisi tanınmadı."
	}
	return c
}

// aptPeriodicEnabled looks for APT::Periodic::Unattended-Upgrade "1" (or
// "always") in apt.conf.d; the last file in name order wins, as in apt.
func aptPeriodicEnabled(fsys fs.FS) bool {
	entries, err := fs.ReadDir(fsys, "etc/apt/apt.conf.d")
	if err != nil {
		return false
	}
	on := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := readSmall(fsys, "etc/apt/apt.conf.d/"+e.Name())
		if err != nil {
			continue
		}
		for _, line := range strings.Split(data, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "//") || !strings.HasPrefix(strings.ToLower(line), "apt::periodic::unattended-upgrade ") {
				continue
			}
			v := strings.Trim(strings.TrimSuffix(strings.TrimSpace(line[len("apt::periodic::unattended-upgrade "):]), ";"), `" `)
			on = v != "0" && v != "" && v != "false"
		}
	}
	return on
}

func checkTimeSync(fsys fs.FS) Check {
	c := Check{ID: "time", Title: "Saat eşitleme", Weight: 5}
	if exists(fsys, "run/systemd/timesync/synchronized") {
		c.Status, c.Detail = Pass, "systemd-timesyncd saati eşitledi."
		return c
	}
	for _, u := range []string{
		"etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service",
		"etc/systemd/system/multi-user.target.wants/chrony.service",
		"etc/systemd/system/multi-user.target.wants/chronyd.service",
		"etc/systemd/system/multi-user.target.wants/ntpsec.service",
		"etc/systemd/system/multi-user.target.wants/ntp.service",
		"etc/systemd/system/multi-user.target.wants/openntpd.service",
	} {
		if exists(fsys, u) {
			c.Status, c.Detail = Pass, "Saat eşitleme servisi etkin ("+u[strings.LastIndexByte(u, '/')+1:]+")."
			return c
		}
	}
	c.Status, c.Detail = Fail, "Etkin bir saat eşitleme servisi bulunamadı; belge ve oturum süreleri saate dayanır."
	c.Fix = "systemctl enable --now systemd-timesyncd (veya chrony)"
	return c
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}

// readSmall reads a configuration file of at most 256 KiB.
func readSmall(fsys fs.FS, name string) (string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() && st.Mode()&fs.ModeSymlink == 0 {
		return "", fs.ErrInvalid
	}
	const limit = 256 << 10
	buf := make([]byte, limit+1)
	n := 0
	for n <= limit {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	if n > limit {
		return "", fmt.Errorf("%s is too large", name)
	}
	return string(buf[:n]), nil
}
