package srvaudit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SSH only through the tunnel (#635, ADR-0184). When the audit finds sshd
// on public addresses, one command binds it to the server's tunnel
// addresses. Lock-out is prevented in four ways:
//  1. it refuses unless the current SSH session already comes through the
//     tunnel (proof that the tunnel path works) or the owner says a console
//     is at hand;
//  2. the new configuration is tested with "sshd -t" before reload;
//  3. before the reload a systemd timer is armed that removes the drop-in
//     and reloads sshd after the rollback delay, even if this process dies;
//  4. the owner confirms from a NEW session through the tunnel, which
//     stops the timer. Without confirmation the old configuration returns.
// Nothing here runs during the read-only audit.

// SSHTunnelDropIn is the drop-in written under sshd_config.d. Its "05"
// prefix makes it the first file sshd reads.
const SSHTunnelDropIn = "etc/ssh/sshd_config.d/05-openscale-tunnel-only.conf"

// sshRollbackUnit is the transient systemd unit of the rollback timer.
const sshRollbackUnit = "openscale-ssh-rollback"

// DefaultSSHRollback is the default confirmation window.
const DefaultSSHRollback = 3 * time.Minute

// SSHSystem is the part of the host the change needs; tests replace it.
type SSHSystem interface {
	// WriteFile and Remove act on paths relative to the root ("/").
	WriteFile(name string, data []byte) error
	Remove(name string) error
	// Run runs a program and returns its combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// HostAddrs lists the addresses configured on the host's interfaces.
	HostAddrs() ([]netip.Addr, error)
	// SessionSource is the client address of the SSH session running this
	// command (SSH_CONNECTION), if any.
	SessionSource() (netip.Addr, bool)
	// Listeners reads the TCP/UDP listening sockets.
	Listeners() []Listener
	Sleep(d time.Duration)
}

// SSHTunnelPlan is what the change would do.
type SSHTunnelPlan struct {
	Addrs    []netip.Addr `json:"addrs"`
	Port     uint16       `json:"port"`
	DropIn   string       `json:"dropIn"`
	Content  string       `json:"content"`
	Service  string       `json:"service"`
	Session  string       `json:"session"` // "tunnel", "public", "none"
	Blockers []string     `json:"blockers,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
	Public   []string     `json:"public,omitempty"` // current public sshd listeners
}

// Ready reports whether the plan may be applied.
func (p SSHTunnelPlan) Ready() bool { return len(p.Blockers) == 0 }

// PlanSSHTunnelOnly inspects the system rooted at fsys. tunnel are the
// network's address ranges (from the signed document); consoleOK accepts a
// session that does not come through the tunnel.
func PlanSSHTunnelOnly(fsys fs.FS, sys SSHSystem, tunnel []netip.Prefix, consoleOK bool) SSHTunnelPlan {
	p := SSHTunnelPlan{DropIn: SSHTunnelDropIn, Port: 22, Service: sshService(fsys)}
	cfg := readSSHD(fsys)
	if cfg == nil {
		p.Blockers = append(p.Blockers, "sshd yapılandırması (/etc/ssh/sshd_config) bulunamadı.")
		return p
	}
	if v, err := strconv.ParseUint(strings.Fields(cfg.get("port", "22") + " ")[0], 10, 16); err == nil && v > 0 {
		p.Port = uint16(v)
	}
	if !includesDropIns(fsys) {
		p.Blockers = append(p.Blockers, "sshd_config, sshd_config.d/*.conf dosyalarını içermiyor (Include yok); bu sürüm desteklenmiyor.")
	}
	if la, ok := cfg.values["listenaddress"]; ok && !ownDropInOnly(fsys) {
		p.Blockers = append(p.Blockers, "sshd yapılandırmasında başka bir ListenAddress var ("+la+"); ListenAddress birikir, önce onu kaldırın.")
	}
	for _, s := range []string{"etc/systemd/system/sockets.target.wants/ssh.socket", "etc/systemd/system/sockets.target.wants/sshd.socket"} {
		if exists(fsys, s) {
			p.Blockers = append(p.Blockers, "sshd soket etkinleştirmesiyle çalışıyor ("+s[strings.LastIndexByte(s, '/')+1:]+"); ListenAddress yok sayılır. 'systemctl disable --now ssh.socket && systemctl enable --now ssh.service' sonrası tekrar deneyin.")
		}
	}
	addrs, err := sys.HostAddrs()
	if err != nil {
		p.Blockers = append(p.Blockers, "Arayüz adresleri okunamadı: "+err.Error())
	}
	for _, a := range addrs {
		a = a.Unmap()
		for _, pf := range tunnel {
			if pf.Contains(a) && !slices.Contains(p.Addrs, a) {
				p.Addrs = append(p.Addrs, a)
			}
		}
	}
	slices.SortFunc(p.Addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(p.Addrs) == 0 {
		p.Blockers = append(p.Blockers, "Bu sunucuda tünel adresi yok: önce sunucuyu cihaz olarak ağa ekleyip 'openscale up' ile tüneli açın (koordinatörün kendi tüneli işletim sistemine arayüz açmaz).")
	}
	switch src, ok := sys.SessionSource(); {
	case !ok:
		p.Session = "none"
		if !consoleOK {
			p.Blockers = append(p.Blockers, "Bu komut SSH oturumu dışında çalışıyor; tünelden erişimin çalıştığı kanıtlanamadı. Konsoldaysanız --i-have-console verin.")
		}
	case inPrefixes(src, tunnel):
		p.Session = "tunnel"
	default:
		p.Session = "public"
		if !consoleOK {
			p.Blockers = append(p.Blockers, "Bu SSH oturumu tünelden gelmiyor ("+src.String()+"). Önce tünel adresinden bağlanın (ssh <kullanıcı>@<tünel-ip>) ve komutu orada çalıştırın.")
		}
	}
	for _, l := range sys.Listeners() {
		if l.Proto == "tcp" && l.Port == p.Port && !inPrefixes(l.Addr, tunnel) && !l.Addr.IsLoopback() {
			p.Public = append(p.Public, netip.AddrPortFrom(l.Addr, l.Port).String())
		}
	}
	if len(p.Public) == 0 && len(p.Addrs) > 0 {
		p.Warnings = append(p.Warnings, "sshd şu an genel bir adreste dinlemiyor görünüyor; değişiklik gerekmeyebilir.")
	}
	var b strings.Builder
	b.WriteString("# OpenScale (#635): sshd yalnızca tünel adreslerinde dinler.\n")
	b.WriteString("# Kaldırmak için: openscale server ssh-tunnel-only --revert\n")
	for _, a := range p.Addrs {
		fmt.Fprintf(&b, "ListenAddress %s\n", a)
	}
	p.Content = b.String()
	return p
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// includesDropIns reports whether sshd_config includes sshd_config.d.
func includesDropIns(fsys fs.FS) bool {
	data, err := readSmall(fsys, "etc/ssh/sshd_config")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(data, "\n") {
		k, v := splitSSHDLine(line)
		if k == "include" && strings.Contains(v, "sshd_config.d") {
			return true
		}
	}
	return false
}

// ownDropInOnly reports whether the only ListenAddress lines are ours (a
// second run of the command).
func ownDropInOnly(fsys fs.FS) bool {
	if !exists(fsys, SSHTunnelDropIn) {
		return false
	}
	without := readSSHDExcept(fsys, SSHTunnelDropIn)
	if without == nil {
		return true
	}
	_, ok := without.values["listenaddress"]
	return !ok
}

// readSSHDExcept reads the configuration as if file did not exist.
func readSSHDExcept(fsys fs.FS, file string) *sshdConfig {
	return readSSHD(exceptFS{FS: fsys, hide: file})
}

type exceptFS struct {
	fs.FS
	hide string
}

func (e exceptFS) Open(name string) (fs.File, error) {
	if name == e.hide {
		return nil, fs.ErrNotExist
	}
	return e.FS.Open(name)
}

func (e exceptFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(e.FS, name)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(entries, func(d fs.DirEntry) bool { return name+"/"+d.Name() == e.hide }), nil
}

func sshService(fsys fs.FS) string {
	for _, d := range unitDirs {
		if exists(fsys, d+"/ssh.service") {
			return "ssh"
		}
	}
	return "sshd"
}

// ApplySSHTunnelOnly writes the drop-in, tests it, arms the rollback timer,
// reloads sshd and checks that it now listens on the tunnel addresses only.
// Any failure before the reload removes the drop-in again.
func ApplySSHTunnelOnly(ctx context.Context, sys SSHSystem, p SSHTunnelPlan, rollback time.Duration) error {
	if !p.Ready() {
		return errors.New("plan has blockers: " + strings.Join(p.Blockers, " "))
	}
	if rollback < 30*time.Second || rollback > 30*time.Minute {
		return errors.New("rollback delay must be 30s-30m")
	}
	if err := sys.WriteFile(p.DropIn, []byte(p.Content)); err != nil {
		return fmt.Errorf("write drop-in: %w", err)
	}
	undo := func() { _ = sys.Remove(p.DropIn) }
	if out, err := sys.Run(ctx, "/usr/sbin/sshd", "-t"); err != nil {
		undo()
		return fmt.Errorf("sshd -t rejected the configuration: %s", strings.TrimSpace(string(out)))
	}
	// The dead man's switch runs as root under systemd, independent of
	// this process and of the SSH session that may be cut by the reload.
	script := fmt.Sprintf("rm -f /%s && (systemctl reload %s || systemctl restart %s)", p.DropIn, p.Service, p.Service)
	_, _ = sys.Run(ctx, "systemctl", "stop", sshRollbackUnit+".timer", sshRollbackUnit+".service")
	if out, err := sys.Run(ctx, "systemd-run", "--unit="+sshRollbackUnit, "--on-active="+strconv.Itoa(int(rollback/time.Second)), "--timer-property=AccuracySec=1s", "/bin/sh", "-c", script); err != nil {
		undo()
		return fmt.Errorf("rollback timer could not be armed, nothing changed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := sys.Run(ctx, "systemctl", "reload", p.Service); err != nil {
		// The timer restores the old configuration; do it now as well.
		undo()
		_, _ = sys.Run(ctx, "systemctl", "reload", p.Service)
		return fmt.Errorf("sshd reload failed, old configuration restored: %s", strings.TrimSpace(string(out)))
	}
	var public []string
	for i := 0; i < 5; i++ {
		sys.Sleep(time.Second)
		public = public[:0]
		listening := false
		for _, l := range sys.Listeners() {
			if l.Proto != "tcp" || l.Port != p.Port {
				continue
			}
			if slices.Contains(p.Addrs, l.Addr.Unmap()) {
				listening = true
			} else if !l.Addr.IsLoopback() {
				public = append(public, netip.AddrPortFrom(l.Addr, l.Port).String())
			}
		}
		if listening && len(public) == 0 {
			return nil
		}
	}
	if len(public) > 0 {
		return fmt.Errorf("sshd still listens on %s; the rollback timer will restore the old configuration", strings.Join(public, ", "))
	}
	return errors.New("sshd does not listen on the tunnel address yet; the rollback timer will restore the old configuration")
}

// ConfirmSSHTunnelOnly stops the rollback timer. Run it from a new session
// through the tunnel.
func ConfirmSSHTunnelOnly(ctx context.Context, sys SSHSystem, tunnel []netip.Prefix) error {
	src, ok := sys.SessionSource()
	if !ok || !inPrefixes(src, tunnel) {
		return errors.New("onay tünelden açılmış yeni bir SSH oturumundan verilmeli")
	}
	if out, err := sys.Run(ctx, "systemctl", "stop", sshRollbackUnit+".timer"); err != nil {
		return fmt.Errorf("rollback timer could not be stopped: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RevertSSHTunnelOnly removes the drop-in and reloads sshd.
func RevertSSHTunnelOnly(ctx context.Context, sys SSHSystem, fsys fs.FS) error {
	if err := sys.Remove(SSHTunnelDropIn); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, _ = sys.Run(ctx, "systemctl", "stop", sshRollbackUnit+".timer")
	if out, err := sys.Run(ctx, "systemctl", "reload", sshService(fsys)); err != nil {
		return fmt.Errorf("sshd reload failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
