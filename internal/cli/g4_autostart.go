package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openscale/openscale/internal/desktop"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/winapp"
)

// "openscale autostart on|off|status|run" (ADR-0194): the desktop part
// starts when the user signs in. The setting ("Oturum açılınca başlat",
// local and unsigned, on by default) is autostart.json in the user's
// config folder; the entries are the Run value (Windows), XDG autostart
// (Linux) or a launch agent (macOS).

func init() {
	registerCommands(
		command{"autostart on", "Oturum açılınca tepsiyi başlatır (bu kullanıcı; --all-users herkes için, yönetici gerekir)", cmdAutostartOn},
		command{"autostart off", "Oturum açılınca başlatmayı kapatır ve bu kullanıcının kaydını siler [--all-users]", cmdAutostartOff},
		command{"autostart status", "Oturum açılışı ayarını ve kayıtlarını gösterir [--json]", cmdAutostartStatus},
		command{"autostart run", "Oturum açılışında çalışır: ayar açıksa tepsiyi başlatır (elle çalıştırılmaz)", cmdAutostartRun},
		command{"tray", "Yalnızca tepsi/menü çubuğu simgesini başlatır; pencere açmaz, parola sormaz (Linux: StatusNotifierItem)", cmdTray},
	)
}

func autostartSettingDir(env *Env) (string, error) {
	if env.DefaultStateDir == nil {
		return "", errors.New("kullanıcı ayar klasörü bilinmiyor")
	}
	return env.DefaultStateDir()
}

// autostartProgram is the program the entry runs: the installed copy when
// there is one, else this program.
func autostartProgram() (string, error) {
	// macOS: run from OpenScale.app, the menu bar app is this program
	// (ADR-0227).
	if runtime.GOOS == "darwin" {
		if exe, err := os.Executable(); err == nil {
			if r, err := filepath.EvalSymlinks(exe); err == nil && strings.Contains(r, ".app/Contents/MacOS/") {
				return r, nil
			}
		}
	}
	if runtime.GOOS == "windows" {
		if dir := winapp.InstallDir(); dir != "" {
			p := filepath.Join(dir, "openscale.exe")
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				return p, nil
			}
		}
	} else {
		for _, p := range []string{"/usr/bin/openscale", "/usr/local/bin/openscale"} {
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return exe, nil
}

func autostartScopeFlag(env *Env, name string, args []string) (svcmgr.Scope, error) {
	fs := newFlagSet(env, name)
	all := fs.Bool("all-users", false, "bütün kullanıcıların kaydı (Windows HKLM, /etc/xdg/autostart, /Library/LaunchAgents; yönetici gerekir)")
	if err := parseFlags(fs, args); err != nil {
		return "", err
	}
	if *all {
		return svcmgr.ScopeAllUsers, nil
	}
	return svcmgr.ScopeUser, nil
}

func cmdAutostartOn(env *Env, args []string) error {
	scope, err := autostartScopeFlag(env, "autostart on", args)
	if err != nil {
		return err
	}
	dir, err := autostartSettingDir(env)
	if err != nil {
		return err
	}
	if err := svcmgr.SaveAutostartSetting(dir, true); err != nil {
		return err
	}
	exe, err := autostartProgram()
	if err != nil {
		return err
	}
	e, err := svcmgr.EnableAutostart(scope, exe)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Oturum açılınca başlat: açık. Kayıt: %s\n", e.Path)
	return nil
}

func cmdAutostartOff(env *Env, args []string) error {
	scope, err := autostartScopeFlag(env, "autostart off", args)
	if err != nil {
		return err
	}
	dir, err := autostartSettingDir(env)
	if err != nil {
		return err
	}
	if err := svcmgr.SaveAutostartSetting(dir, false); err != nil {
		return err
	}
	removed, err := svcmgr.DisableAutostart(scope)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Oturum açılınca başlat: kapalı.")
	if removed {
		fmt.Fprintln(env.Stdout, "Başlangıç kaydı silindi.")
	}
	if scope == svcmgr.ScopeUser {
		if all, err := svcmgr.AutostartState(svcmgr.ScopeAllUsers); err == nil && all.Installed {
			fmt.Fprintln(env.Stdout, "Bütün kullanıcılar için kayıt duruyor; bu kullanıcının ayarı kapalı olduğu için tepsi başlamaz.")
		}
	}
	return nil
}

// autostartStatus is the JSON of "autostart status".
type autostartStatus struct {
	Schema   int                     `json:"schema"`
	Enabled  bool                    `json:"enabled"`
	Setting  string                  `json:"setting_file"`
	Entries  []svcmgr.AutostartEntry `json:"entries"`
	Warnings []string                `json:"warnings,omitempty"`
}

func cmdAutostartStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "autostart status")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, err := autostartSettingDir(env)
	if err != nil {
		return err
	}
	st := autostartStatus{Schema: 1, Setting: filepath.Join(dir, svcmgr.AutostartSettingFile)}
	on, serr := svcmgr.LoadAutostartSetting(dir)
	st.Enabled = on
	if serr != nil {
		st.Warnings = append(st.Warnings, serr.Error())
	}
	for _, scope := range []svcmgr.Scope{svcmgr.ScopeUser, svcmgr.ScopeAllUsers} {
		e, err := svcmgr.AutostartState(scope)
		if err != nil && !errors.Is(err, svcmgr.ErrUnsupported) {
			st.Warnings = append(st.Warnings, err.Error())
		}
		st.Entries = append(st.Entries, e)
	}
	if *asJSON {
		return printJSON(env.Stdout, st)
	}
	state := "kapalı"
	if st.Enabled {
		state = "açık"
	}
	fmt.Fprintf(env.Stdout, "Oturum açılınca başlat: %s (%s)\n", state, st.Setting)
	for _, e := range st.Entries {
		who := "bu kullanıcı"
		if e.Scope == svcmgr.ScopeAllUsers {
			who = "bütün kullanıcılar"
		}
		switch {
		case !e.Installed:
			fmt.Fprintf(env.Stdout, "  %s: kayıt yok (%s)\n", who, e.Path)
		case !e.Ours:
			fmt.Fprintf(env.Stdout, "  %s: OpenScale'e ait olmayan kayıt (%s)\n", who, e.Path)
		default:
			fmt.Fprintf(env.Stdout, "  %s: kayıtlı (%s)\n", who, e.Path)
		}
	}
	for _, w := range st.Warnings {
		fmt.Fprintln(env.Stdout, "  uyarı: "+w)
	}
	return nil
}

// cmdAutostartRun is what the sign-in entry runs. With the setting off it
// exits at once. On Windows it starts the desktop app (tray and service),
// on macOS the menu bar app (ADR-0227), on Linux the StatusNotifierItem
// tray (ADR-0234); elsewhere it only reports.
func cmdAutostartRun(env *Env, args []string) error {
	if err := parseFlags(newFlagSet(env, "autostart run"), args); err != nil {
		return err
	}
	dir, err := autostartSettingDir(env)
	if err != nil {
		return err
	}
	if on, _ := svcmgr.LoadAutostartSetting(dir); !on {
		return nil
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		fmt.Fprintln(env.Stderr, "Bu sistemde tepsi simgesi yok; panel için: openscale window --dir <ağ klasörü>")
		return nil
	}
	return desktop.RunAppQuiet(env.Ctx) // W2: tray only, no window at sign-in
}

// trimLower is shared by G4 commands.
func trimLower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// cmdTray starts the tray icon without the window (ADR-0234): what the
// sign-in entry runs once the setting allowed it, here for a manual start.
func cmdTray(env *Env, args []string) error {
	if err := parseFlags(newFlagSet(env, "tray"), args); err != nil {
		return err
	}
	return desktop.RunAppQuiet(env.Ctx)
}
