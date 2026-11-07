package svcmgr

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/member"
)

// The systemd side of the package. It is plain file and command work
// behind sysOps, so the tests run on every system against a temporary
// root and a recorded command list; svcmgr_linux.go wires the real
// system.

//go:embed units/*
var unitFiles embed.FS

// Paths of a Linux installation.
const (
	etcUnitDir      = "/etc/systemd/system"
	pkgUnitDir      = "/usr/lib/systemd/system"
	pkgUnitDirOld   = "/lib/systemd/system"
	packageBinary   = "/usr/bin/openscale"
	localBinary     = "/usr/local/bin/openscale"
	paramsDir       = "/etc/openscale"
	dropInName      = "50-openscale-install.conf"
	waitOnlineUnit  = "openscale-wait-online.service"
	networkdConfDir = "/etc/systemd/networkd.conf.d"
	networkdNetDir  = "/etc/systemd/network"
	nmConfDir       = "/etc/NetworkManager/conf.d"
	serviceUser     = "openscale"
	// installMarker is the first line of every file "service install"
	// writes; uninstall removes only files that carry it.
	installMarker = "# Installed by \"openscale service install\"; \"openscale service uninstall\" removes it."
	// templateBinary is the program path in the deploy/linux units.
	templateBinary = "/usr/local/bin/openscale"
	maxUnitFile    = 64 << 10
)

// sysOps is how the systemd code touches the system.
type sysOps struct {
	// root prefixes every path (tests); "" is the real system.
	root       string
	run        func(ctx context.Context, name string, args ...string) ([]byte, error)
	executable func() (string, error)
	euid       func() int
	// ensureUser creates the coordinator's system user if needed and
	// returns its ids.
	ensureUser func(ctx context.Context) (uid, gid int, err error)
	chown      func(path string, uid, gid int) error
	// trusted checks that only root can change a program and its folders
	// (F-124).
	trusted func(path string) error
}

func (s sysOps) path(p string) string {
	if s.root == "" {
		return p
	}
	return filepath.Join(s.root, filepath.FromSlash(p))
}

func (s sysOps) exists(p string) bool {
	_, err := os.Stat(s.path(p))
	return err == nil
}

func (s sysOps) systemctl(ctx context.Context, args ...string) ([]byte, error) {
	return s.run(ctx, "systemctl", args...)
}

// installLinux installs or updates a role's unit.
func installLinux(ctx context.Context, s sysOps, o Options) (Result, error) {
	o, err := o.normalize()
	if err != nil {
		return Result{}, err
	}
	if s.euid() != 0 {
		return Result{}, fmt.Errorf("%w: sudo openscale service install --role %s ...", ErrNeedsRoot, o.Role)
	}
	var res Result
	bin, note, err := installBinary(s)
	if err != nil {
		return res, err
	}
	res.Binary = bin
	if note != "" {
		res.Notes = append(res.Notes, note)
	}
	if err := s.trusted(s.path(bin)); err != nil {
		return res, fmt.Errorf("servis programı güvenli bir yerde değil (F-124): %w", err)
	}
	unit := o.Role.Unit()
	if err := writeBaseUnit(s, unit, bin); err != nil {
		return res, err
	}
	if err := prepareStateDir(ctx, s, o); err != nil {
		return res, err
	}
	params := paramsDir + "/" + string(o.Role) + ".json"
	if err := writeParams(s, params, o); err != nil {
		return res, err
	}
	if err := writeFile(s, unitDropIn(unit), []byte(dropIn(o, bin, params)), 0o644); err != nil {
		return res, err
	}
	if o.Role == RoleDevice {
		if err := writeBaseUnit(s, waitOnlineUnit, bin); err != nil {
			return res, err
		}
		wait := installMarker + "\n[Service]\nExecStart=\nExecStart=" + bin + " wait --state-dir " + o.StateDir + " --timeout 120s --quiet\n"
		if err := writeFile(s, unitDropIn(waitOnlineUnit), []byte(wait), 0o644); err != nil {
			return res, err
		}
		res.Notes = append(res.Notes, networkManagerFiles(s, o.Interface)...)
		res.Notes = append(res.Notes, installSystemAutostart(s, "linux", bin)...) // ADR-0194
	}
	if _, err := s.systemctl(ctx, "daemon-reload"); err != nil {
		return res, fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	joined, why := joinedLinux(s, o)
	switch {
	case !joined:
		res.Notes = append(res.Notes, why+"; birim kuruldu ama etkinleştirilmedi. Katıldıktan sonra: openscale service install --role "+string(o.Role))
	case o.NoStart:
		if _, err := s.systemctl(ctx, "enable", unit); err != nil {
			return res, fmt.Errorf("systemctl enable: %w", err)
		}
		res.Notes = append(res.Notes, "Birim açılışta başlayacak; şimdi başlatmak için: openscale service start --role "+string(o.Role))
	default:
		if _, err := s.systemctl(ctx, "enable", unit); err != nil {
			return res, fmt.Errorf("systemctl enable: %w", err)
		}
		// restart picks up new parameters when the unit already ran.
		if _, err := s.systemctl(ctx, "restart", unit); err != nil {
			return res, fmt.Errorf("systemctl restart: %w", err)
		}
		res.Started = true
	}
	return res, nil
}

// installBinary returns the program the unit runs: the Debian package's
// /usr/bin/openscale when present, else a copy of this program in
// /usr/local/bin.
func installBinary(s sysOps) (string, string, error) {
	if s.exists(packageBinary) {
		return packageBinary, "Paketle kurulan " + packageBinary + " kullanılıyor; güncelleme paketle yapılır.", nil
	}
	src, err := s.executable()
	if err != nil {
		return "", "", fmt.Errorf("program yolu bulunamadı: %w", err)
	}
	dst := s.path(localBinary)
	if same, err := sameFile(src, dst); err != nil {
		return "", "", err
	} else if same {
		return localBinary, "", nil
	}
	if err := copyProgram(src, dst); err != nil {
		return "", "", err
	}
	return localBinary, "Program " + localBinary + " konumuna kopyalandı.", nil
}

func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, fmt.Errorf("program okunamadı: %w", err)
	}
	bi, err := os.Stat(b)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if os.SameFile(ai, bi) {
		return true, nil
	}
	if ai.Size() != bi.Size() {
		return false, nil
	}
	da, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	db, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(da, db), nil
}

// copyProgram writes src to dst atomically with mode 0755.
func copyProgram(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("program açılamadı: %w", err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".openscale-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("program kopyalanamadı: %w", err)
	}
	if err = tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// writeBaseUnit writes the unit to /etc/systemd/system unless a package
// or the administrator already installed one; the drop-in then adapts
// whichever is there.
func writeBaseUnit(s sysOps, unit, bin string) error {
	for _, dir := range []string{pkgUnitDir, pkgUnitDirOld, etcUnitDir} {
		if s.exists(dir + "/" + unit) {
			return nil
		}
	}
	data, err := unitFiles.ReadFile("units/" + unit)
	if err != nil {
		return err
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), templateBinary+" ", bin+" ")
	return writeFile(s, etcUnitDir+"/"+unit, []byte(installMarker+"\n"+text), 0o644)
}

func unitDropIn(unit string) string { return etcUnitDir + "/" + unit + ".d/" + dropInName }

// dropIn points the unit at the saved parameters.
func dropIn(o Options, bin, params string) string {
	var b strings.Builder
	b.WriteString(installMarker + "\n[Service]\nExecStart=\n")
	if o.Role == RoleCoordinator {
		fmt.Fprintf(&b, "ExecStart=%s coordinator run --config %s\n", bin, params)
	} else {
		fmt.Fprintf(&b, "ExecStart=%s up --config %s\n", bin, params)
	}
	fmt.Fprintf(&b, "ReadWritePaths=%s\n", o.StateDir)
	if o.Role == RoleCoordinator && o.TCPListen != "" {
		// Ports below 1024 need this capability; the unit grants it
		// already, repeated here for units written by an older version.
		b.WriteString("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n")
	}
	return b.String()
}

// writeParams saves the installation parameters as a --config file. It
// holds no secret (the commands refuse secrets from it), so it is
// world-readable for the coordinator's own user.
func writeParams(s sysOps, p string, o Options) error {
	m := map[string]any{"state-dir": o.StateDir, "listen-port": o.ListenPort}
	if o.Role == RoleDevice {
		m["interface"] = o.Interface
	}
	if o.TCPListen != "" {
		m["tcp-listen"] = o.TCPListen
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(s, p, append(data, '\n'), 0o644)
}

func prepareStateDir(ctx context.Context, s sysOps, o Options) error {
	if err := os.MkdirAll(s.path(path.Dir(o.StateDir)), 0o755); err != nil {
		return fmt.Errorf("durum klasörü oluşturulamadı: %w", err)
	}
	dir := s.path(o.StateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("durum klasörü oluşturulamadı: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if o.Role != RoleCoordinator {
		return nil
	}
	uid, gid, err := s.ensureUser(ctx)
	if err != nil {
		return fmt.Errorf("%s kullanıcısı oluşturulamadı: %w", serviceUser, err)
	}
	return s.chown(dir, uid, gid)
}

// networkManagerFiles keeps systemd-networkd and NetworkManager away from
// the tunnel interface and its routes (F-150). Files are written only for
// the managers that are installed; nothing is restarted.
func networkManagerFiles(s sysOps, iface string) []string {
	var notes []string
	write := func(dst, src string) bool {
		data, err := unitFiles.ReadFile("units/" + src)
		if err != nil {
			return false
		}
		text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "OpenScale", iface)
		return writeFile(s, dst, []byte(installMarker+"\n"+text), 0o644) == nil
	}
	if s.exists("/usr/lib/systemd/systemd-networkd") || s.exists("/lib/systemd/systemd-networkd") {
		ok1 := write(networkdConfDir+"/50-openscale.conf", "50-openscale-networkd.conf")
		ok2 := write(networkdNetDir+"/50-openscale.network", "50-openscale.network")
		if ok1 && ok2 {
			notes = append(notes, "systemd-networkd OpenScale rotalarına dokunmayacak şekilde ayarlandı; etkin olması için systemd-networkd yeniden başlatılmalı veya bilgisayar yeniden açılmalı.")
		}
	}
	if s.exists("/etc/NetworkManager") {
		if write(nmConfDir+"/50-openscale.conf", "50-openscale-networkmanager.conf") {
			notes = append(notes, "NetworkManager OpenScale arayüzünü yönetmeyecek şekilde ayarlandı; etkin olması için: nmcli general reload conf")
		}
	}
	return notes
}

func joinedLinux(s sysOps, o Options) (bool, string) {
	if _, err := member.Open(s.path(o.StateDir)); err != nil {
		return false, o.StateDir + " henüz bir ağa katılmamış"
	}
	key := "device.key"
	if o.Role == RoleCoordinator {
		key = "coordinator.key"
	}
	if !s.exists(o.StateDir + "/" + key) {
		return false, o.StateDir + " içinde " + key + " yok"
	}
	return true, ""
}

func writeFile(s sysOps, p string, data []byte, perm os.FileMode) error {
	full := s.path(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("%s yazılamadı: %w", p, err)
	}
	tmp := full + ".openscale-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("%s yazılamadı: %w", p, err)
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s yazılamadı: %w", p, err)
	}
	return nil
}

// removeOwned deletes a file only if "service install" wrote it.
func removeOwned(s sysOps, p string) (bool, error) {
	full := s.path(p)
	f, err := os.Open(full)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	line, _ := bufio.NewReader(io.LimitReader(f, maxUnitFile)).ReadString('\n')
	_ = f.Close()
	if strings.TrimRight(line, "\r\n") != installMarker {
		return false, nil
	}
	if err := os.Remove(full); err != nil {
		return false, err
	}
	_ = os.Remove(filepath.Dir(full)) // the .d folder, when empty
	return true, nil
}

func controlLinux(ctx context.Context, s sysOps, verb string, r Role) error {
	if s.euid() != 0 {
		return fmt.Errorf("%w: sudo openscale service %s --role %s", ErrNeedsRoot, verb, r)
	}
	if _, err := s.systemctl(ctx, verb, r.Unit()); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", verb, r.Unit(), err)
	}
	return nil
}

func statusLinux(ctx context.Context, s sysOps, r Role) (Status, error) {
	out, err := s.systemctl(ctx, "show", r.Unit(), "--no-pager",
		"-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState", "-p", "MainPID", "-p", "StatusText", "-p", "FragmentPath")
	if err != nil {
		return Status{}, fmt.Errorf("systemctl show: %w", err)
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	st := Status{
		Installed: props["LoadState"] == "loaded",
		State:     props["ActiveState"],
		Detail:    props["StatusText"],
		Binary:    props["FragmentPath"],
	}
	if sub := props["SubState"]; sub != "" && st.State != "" {
		st.State += " (" + sub + ")"
	}
	st.Running = props["ActiveState"] == "active"
	st.Enabled = props["UnitFileState"] == "enabled"
	if pid, err := strconv.Atoi(props["MainPID"]); err == nil {
		st.PID = pid
	}
	if !st.Installed {
		st.State = "kurulu değil"
	}
	return st, nil
}

func uninstallLinux(ctx context.Context, s sysOps, r Role) ([]string, error) {
	if s.euid() != 0 {
		return nil, fmt.Errorf("%w: sudo openscale service uninstall --role %s", ErrNeedsRoot, r)
	}
	var notes []string
	units := []string{r.Unit()}
	if r == RoleDevice {
		units = append([]string{waitOnlineUnit}, units...)
	}
	for _, u := range units {
		// A unit that is not loaded is fine: there is nothing to stop.
		_, _ = s.systemctl(ctx, "disable", "--now", u)
		if _, err := removeOwned(s, unitDropIn(u)); err != nil {
			return notes, err
		}
		if removed, err := removeOwned(s, etcUnitDir+"/"+u); err != nil {
			return notes, err
		} else if removed {
			notes = append(notes, etcUnitDir+"/"+u+" kaldırıldı.")
		}
	}
	if r == RoleDevice {
		for _, p := range []string{networkdConfDir + "/50-openscale.conf", networkdNetDir + "/50-openscale.network", nmConfDir + "/50-openscale.conf"} {
			if removed, err := removeOwned(s, p); err != nil {
				return notes, err
			} else if removed {
				notes = append(notes, p+" kaldırıldı.")
			}
		}
		autoNotes, _ := removeSystemAutostart(s, "linux") // ADR-0194
		notes = append(notes, autoNotes...)
	}
	if _, err := s.systemctl(ctx, "daemon-reload"); err != nil {
		return notes, fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	notes = append(notes, "Durum klasörü (anahtarlar) ve "+paramsDir+"/"+string(r)+".json yerinde bırakıldı.")
	return notes, nil
}
