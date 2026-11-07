package cli

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/svcmgr"
)

// Service management commands (F-148, #307): the same verbs on Windows
// (one OpenScale service) and on Linux (systemd units per role).

func serviceCommands() []command {
	return []command{
		{"service install", "Servisi kurar veya günceller ve başlatır (Windows: yönetici; Linux: root, --role device|coordinator)", cmdServiceInstall},
		{"service start", "Servisi başlatır", cmdServiceStart},
		{"service stop", "Servisi durdurur (kill switch filtreleri yerinde kalır)", cmdServiceStop},
		{"service restart", "Servisi yeniden başlatır", cmdServiceRestart},
		{"service status", "Servisin kurulu ve çalışır olduğunu gösterir (--json)", cmdServiceStatus},
		{"wait", "Tünel hazır olana kadar bekler (açılış betikleri ve systemd için; --timeout)", cmdWait},
	}
}

var (
	svcInstall   = svcmgr.Install
	svcStart     = svcmgr.Start
	svcStop      = svcmgr.Stop
	svcRestart   = svcmgr.Restart
	svcGet       = svcmgr.Get
	svcUninstall = svcmgr.Uninstall
)

func addRoleFlag(fs interface {
	String(name, value, usage string) *string
}) *string {
	return fs.String("role", "device", "Linux birimi: device (tünel) veya coordinator; Windows'ta tek servis vardır")
}

func cmdServiceInstall(env *Env, args []string) error {
	fs := newFlagSet(env, "service install")
	role := addRoleFlag(fs)
	stateDir := fs.String("state-dir", "", "durum klasörü (Linux; varsayılan /var/lib/openscale/<rol>)")
	port := fs.Int("listen-port", 0, "UDP portu (Linux; varsayılan cihaz 41821, koordinatör 41820)")
	iface := fs.String("interface", "", "tünel arayüzü adı (Linux cihaz; varsayılan OpenScale)")
	tcpListen := fs.String("tcp-listen", "", "koordinatörün TCP dinleme adresi, ör. :443 (Linux koordinatör; ADR-0032)")
	noStart := fs.Bool("no-start", false, "kur ama şimdi başlatma")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	r, err := svcmgr.ParseRole(*role)
	if err != nil {
		return usageError("%v", err)
	}
	if *tcpListen != "" {
		if _, _, _, err := (coordinatorTCPFlags{listen: tcpListen, maxConns: new(int), perIP: new(int)}).resolve(); err != nil {
			return err
		}
	}
	res, err := svcInstall(envContext(env), svcmgr.Options{Role: r, StateDir: *stateDir, ListenPort: *port,
		Interface: *iface, TCPListen: *tcpListen, NoStart: *noStart})
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "OpenScale servisi kuruldu: %s\n", res.Binary)
	for _, n := range res.Notes {
		fmt.Fprintf(w, "  - %s\n", n)
	}
	if res.Started {
		fmt.Fprintln(w, "Servis çalışıyor. Durum için: openscale service status")
	}
	return nil
}

func serviceControl(env *Env, name string, args []string, do func(r svcmgr.Role) error, done string) error {
	fs := newFlagSet(env, name)
	role := addRoleFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	r, err := svcmgr.ParseRole(*role)
	if err != nil {
		return usageError("%v", err)
	}
	if err := do(r); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, done)
	return nil
}

func cmdServiceStart(env *Env, args []string) error {
	return serviceControl(env, "service start", args, func(r svcmgr.Role) error { return svcStart(envContext(env), r) }, "Servis başlatıldı.")
}

func cmdServiceStop(env *Env, args []string) error {
	return serviceControl(env, "service stop", args, func(r svcmgr.Role) error { return svcStop(envContext(env), r) },
		"Servis durduruldu. Kill switch açıksa filtreler yerinde kalır; kaldırmak için: openscale killswitch off")
}

func cmdServiceRestart(env *Env, args []string) error {
	return serviceControl(env, "service restart", args, func(r svcmgr.Role) error { return svcRestart(envContext(env), r) }, "Servis yeniden başlatıldı.")
}

func cmdServiceStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "service status")
	role := addRoleFlag(fs)
	jsonOut := fs.Bool("json", false, "makine okunur JSON çıktı (\"schema\": 1)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	r, err := svcmgr.ParseRole(*role)
	if err != nil {
		return usageError("%v", err)
	}
	st, err := svcGet(envContext(env), r)
	if err != nil {
		return err
	}
	if *jsonOut {
		if err := printJSON(env.Stdout, map[string]any{"schema": panel.DiagSchema, "role": string(r), "service": st}); err != nil {
			return err
		}
	} else {
		w := env.Stdout
		fmt.Fprintf(w, "durum:    %s\n", st.State)
		fmt.Fprintf(w, "kurulu:   %s\n", yesNo(st.Installed))
		fmt.Fprintf(w, "açılışta: %s\n", yesNo(st.Enabled))
		if st.Binary != "" {
			fmt.Fprintf(w, "program:  %s\n", st.Binary)
		}
		if st.PID > 0 {
			fmt.Fprintf(w, "PID:      %d\n", st.PID)
		}
		if st.Detail != "" {
			fmt.Fprintf(w, "ayrıntı:  %s\n", st.Detail)
		}
	}
	if !st.Running {
		return errors.New("servis çalışmıyor")
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "evet"
	}
	return "hayır"
}

// cmdServiceUninstallUnix removes the systemd unit of a role.
func cmdServiceUninstallUnix(env *Env, args []string) error {
	fs := newFlagSet(env, "service uninstall")
	role := addRoleFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	r, err := svcmgr.ParseRole(*role)
	if err != nil {
		return usageError("%v", err)
	}
	notes, err := svcUninstall(envContext(env), r)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s kaldırıldı.\n", r.Unit())
	for _, n := range notes {
		fmt.Fprintf(env.Stdout, "  - %s\n", n)
	}
	return nil
}

// serviceUninstallElsewhere reports whether "service uninstall" is the
// systemd variant here.
func serviceUninstallElsewhere() bool { return runtime.GOOS != "windows" }
