package svcmgr

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/launchd"
	"github.com/openscale/openscale/internal/securefile"
)

// Start at sign-in (ADR-0194). The background service already starts at
// boot on every system (Windows StartAutomatic, systemd "enable" with
// WantedBy=multi-user.target, launchd RunAtLoad in /Library/LaunchDaemons).
// The desktop part (tray and window) starts when a user signs in:
//
//   - Windows: the "OpenScale" value under ...\CurrentVersion\Run, HKCU
//     for one user, HKLM for every user (internal/winapp);
//   - Linux: XDG autostart, ~/.config/autostart/openscale-tray.desktop or
//     /etc/xdg/autostart/openscale-tray.desktop;
//   - macOS: a launch agent with RunAtLoad, ~/Library/LaunchAgents or
//     /Library/LaunchAgents/com.openscale.tray.plist.
//
// Each entry runs "openscale autostart run", which first reads the user's
// "start at sign-in" setting (local, unsigned, on by default) and exits
// when it is off. So an all-users entry written by the installer never
// overrides a user who turned the setting off.

// Scope selects the user's own entry or the entry for every user.
type Scope string

const (
	ScopeUser     Scope = "user"
	ScopeAllUsers Scope = "all"
)

// ParseScope accepts user (default) and all.
func ParseScope(s string) (Scope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "user", "kullanıcı", "kullanici":
		return ScopeUser, nil
	case "all", "all-users", "tümü", "tumu", "herkes":
		return ScopeAllUsers, nil
	}
	return "", fmt.Errorf("kapsam %q geçersiz; user veya all yazın", s)
}

// Names of the sign-in entries.
const (
	AutostartLabel       = "com.openscale.tray"
	AutostartDesktopFile = "openscale-tray.desktop"
	// LegacyAutostartDesktopFile is the Linux entry's name before
	// 1.0.0-beta.2; OpenScale removes its own old entry whenever it writes
	// or removes the new one (ADR-0234).
	LegacyAutostartDesktopFile = "openscale.desktop"
	SystemXDGAutostart         = "/etc/xdg/autostart"
	// AutostartSettingFile is the user's setting in the user config dir.
	AutostartSettingFile = "autostart.json"
)

// autostartMarker marks entries written by OpenScale; only those are
// removed.
const autostartMarker = "# Installed by openscale; \"openscale autostart off\" or \"openscale service uninstall\" removes it."

// launchAgentMarker is the XML comment of the launch agent (no "--").
const launchAgentMarker = "Installed by openscale; openscale autostart off or openscale service uninstall removes it."

// AutostartArgs are the arguments every entry passes to the program.
func AutostartArgs() []string { return []string{"autostart", "run"} }

// ErrBadProgramPath: the program path cannot be written into an entry.
var ErrBadProgramPath = errors.New("başlangıç kaydı için program yolu geçersiz")

// desktopExecArg quotes one Exec argument by the Desktop Entry
// Specification: inside double quotes, backslash escapes ", `, $ and \.
func desktopExecArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'`$\\><~|&;*?#()") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '`' || r == '$' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func validProgram(exe string) error {
	if !strings.HasPrefix(exe, "/") || len(exe) > 1024 || strings.ContainsFunc(exe, func(r rune) bool { return r < 0x20 || r == 0x7f }) || strings.Contains(exe, "%") {
		return ErrBadProgramPath
	}
	return nil
}

// DesktopEntry renders the XDG autostart file. Values are escaped by the
// specification; "%" in the path is refused because Exec gives it field
// code meaning.
func DesktopEntry(exe string) ([]byte, error) {
	if err := validProgram(exe); err != nil {
		return nil, err
	}
	// "\" in a value is an escape character of the desktop file format
	// itself, so the Exec line is escaped once more.
	execLine := desktopExecArg(exe) + " " + strings.Join(AutostartArgs(), " ")
	execLine = strings.ReplaceAll(execLine, `\`, `\\`)
	var b strings.Builder
	b.WriteString(autostartMarker + "\n")
	b.WriteString("[Desktop Entry]\n")
	b.WriteString("Type=Application\n")
	b.WriteString("Name=OpenScale\n")
	b.WriteString("Comment=OpenScale tepsi simgesi (oturum açılınca başlar)\n")
	b.WriteString("Exec=" + execLine + "\n")
	b.WriteString("Icon=openscale\n")
	b.WriteString("Terminal=false\n")
	b.WriteString("NoDisplay=true\n")
	b.WriteString("X-GNOME-Autostart-enabled=true\n")
	return []byte(b.String()), nil
}

// LaunchAgentPlist renders the macOS launch agent.
func LaunchAgentPlist(exe string) ([]byte, error) {
	if err := validProgram(exe); err != nil {
		return nil, err
	}
	return launchd.Plist(launchd.Job{
		Label:     AutostartLabel,
		Program:   append([]string{exe}, AutostartArgs()...),
		Marker:    launchAgentMarker,
		RunAtLoad: true,
		Agent:     true,
	})
}

// UserAutostartPath is the user's entry on Linux (goos "linux") or macOS
// ("darwin"); configHome is $XDG_CONFIG_HOME (may be empty).
func UserAutostartPath(goos, home, configHome string) (string, error) {
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("ev klasörü bulunamadı")
	}
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", AutostartLabel+".plist"), nil
	case "linux", "freebsd", "openbsd", "netbsd":
		base := filepath.Join(home, ".config")
		// The XDG specification ignores a relative XDG_CONFIG_HOME.
		if configHome != "" && filepath.IsAbs(configHome) {
			base = configHome
		}
		return filepath.Join(base, "autostart", AutostartDesktopFile), nil
	}
	return "", ErrUnsupported
}

// SystemAutostartPath is the entry for every user.
func SystemAutostartPath(goos string) (string, error) {
	switch goos {
	case "darwin":
		return launchd.AgentDir + "/" + AutostartLabel + ".plist", nil
	case "linux", "freebsd", "openbsd", "netbsd":
		return SystemXDGAutostart + "/" + AutostartDesktopFile, nil
	}
	return "", ErrUnsupported
}

// RenderAutostart renders the entry of goos.
func RenderAutostart(goos, exe string) ([]byte, error) {
	if goos == "darwin" {
		return LaunchAgentPlist(exe)
	}
	return DesktopEntry(exe)
}

// hasAutostartMarker reports whether data is an entry OpenScale wrote.
func hasAutostartMarker(data []byte) bool {
	if launchd.HasMarker(data, launchAgentMarker) {
		return true
	}
	line, _ := bufio.NewReader(bytes.NewReader(data)).ReadString('\n')
	return strings.TrimRight(line, "\r\n") == autostartMarker
}

const maxAutostartFile = 64 << 10

// AutostartEntry describes one entry.
type AutostartEntry struct {
	Scope Scope  `json:"scope"`
	Path  string `json:"path,omitempty"`
	// Installed: the entry exists. Ours: OpenScale wrote it.
	Installed bool `json:"installed"`
	Ours      bool `json:"ours"`
	// Program is the program the entry runs (Windows).
	Program string `json:"program,omitempty"`
}

// writeAutostartFile writes an entry file without following a link at
// the destination.
func writeAutostartFile(path string, data []byte, dirPerm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("%s yazılamadı: %w", path, err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s düzenli bir dosya değil; dokunulmadı", path)
		}
		old, err := os.ReadFile(path)
		if err == nil && !hasAutostartMarker(old) {
			return fmt.Errorf("%s OpenScale tarafından yazılmamış; dokunulmadı", path)
		}
	}
	tmp := path + ".openscale-tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("%s yazılamadı: %w", path, err)
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s yazılamadı: %w", path, errors.Join(werr, cerr))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s yazılamadı: %w", path, err)
	}
	return nil
}

// removeAutostartFile deletes an entry only when OpenScale wrote it.
func removeAutostartFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s düzenli bir dosya değil; dokunulmadı", path)
	}
	data, err := readLimited(path)
	if err != nil {
		return false, err
	}
	if !hasAutostartMarker(data) {
		return false, fmt.Errorf("%s OpenScale tarafından yazılmamış; dokunulmadı", path)
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	return true, nil
}

func autostartFileState(scope Scope, path string) (AutostartEntry, error) {
	e := AutostartEntry{Scope: scope, Path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	e.Installed = true
	if info.Mode().IsRegular() {
		if data, err := readLimited(path); err == nil {
			e.Ours = hasAutostartMarker(data)
		}
	}
	return e, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxAutostartFile))
}

// AutostartSetting is the user's "start at sign-in" choice.
type AutostartSetting struct {
	Enabled bool `json:"enabled"`
}

// LoadAutostartSetting reads the setting from the user's config dir; a
// missing file means on (the owner's default). A damaged file is an
// error and means on as well, which only starts the tray.
func LoadAutostartSetting(dir string) (bool, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, AutostartSettingFile), 4<<10)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s AutostartSetting
	if err := dec.Decode(&s); err != nil {
		return true, fmt.Errorf("%s bozuk: %w", AutostartSettingFile, err)
	}
	return s.Enabled, nil
}

// SaveAutostartSetting writes the setting (0600, in an 0700 folder).
func SaveAutostartSetting(dir string, enabled bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(AutostartSetting{Enabled: enabled})
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, AutostartSettingFile), data)
}

// removeLegacyAutostart deletes the pre-1.0.0-beta.2 entry beside path
// when OpenScale wrote it; someone else's file stays.
func removeLegacyAutostart(path string) bool {
	if filepath.Base(path) != AutostartDesktopFile {
		return false
	}
	removed, err := removeAutostartFile(filepath.Join(filepath.Dir(path), LegacyAutostartDesktopFile))
	return err == nil && removed
}

// legacyAutostartState reports the old entry when the new one is missing.
func legacyAutostartState(e AutostartEntry) AutostartEntry {
	if e.Installed || filepath.Base(e.Path) != AutostartDesktopFile {
		return e
	}
	old, err := autostartFileState(e.Scope, filepath.Join(filepath.Dir(e.Path), LegacyAutostartDesktopFile))
	if err == nil && old.Installed {
		return old
	}
	return e
}
