package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
)

// environ is os.Environ; tests replace it.
var environ = os.Environ

// declareUpBaseFlags mirrors the flags cmdUp declares itself, so a
// configuration file can be checked without starting a tunnel.
func declareUpBaseFlags(fs flagDeclarer) (mtu *int) {
	fs.String("state-dir", "", "")
	fs.String("network-dir", "", "")
	fs.Int("listen-port", 0, "")
	fs.String("interface", defaultInterfaceName, "")
	fs.String("exit-node", "", "")
	fs.String("exit-dns-upstream", "", "")
	fs.String("exit-upstream", "", "") // ADR-0142
	fs.String("netfilter-mode", "auto", "")
	mtu = fs.Int("mtu", node.DefaultMTU, "")
	fs.Bool("force-relay", false, "")
	fs.Duration("relay-after", 0, "")
	fs.Duration("direct-retry", 0, "")
	fs.Bool("network-dns", true, "")
	fs.Bool("debug", false, "")
	return mtu
}

// flagDeclarer is the part of flag.FlagSet declareUpBaseFlags uses.
type flagDeclarer interface {
	String(name, value, usage string) *string
	Int(name string, value int, usage string) *int
	Bool(name string, value bool, usage string) *bool
	Duration(name string, value time.Duration, usage string) *time.Duration
}

// checkUpConfig validates the environment and a configuration file of
// "openscale up" or "coordinator run" the way those commands read them.
func checkUpConfig(env *Env, command, path string) []service.Finding {
	var out []service.Finding
	add := func(level, msg string) {
		out = append(out, service.Finding{Level: level, Area: "yapılandırma", Message: msg})
	}
	fs := newFlagSet(env, command)
	fs.SetOutput(discard{})
	allowed := upEnvFlags
	var resolve func() error
	if command == "coordinator run" {
		allowed = coordinatorEnvFlags
		fs.String("state-dir", "", "")
		fs.Int("listen-port", defaultCoordinatorPort, "")
		rate := fs.Int64("relay-rate", 0, "")
		burst := fs.Int64("relay-burst", 0, "")
		fs.Bool("debug", false, "")
		tcp := addCoordinatorTCPFlags(fs)
		resolve = func() error {
			if err := validRelayFlags(*rate, *burst); err != nil {
				return err
			}
			_, _, _, err := tcp.resolve()
			return err
		}
	} else {
		nf := addUpNetFlags(fs)
		tf := addUpTransportFlags(fs)
		addUpDNSEnforceFlags(fs) // #717, ADR-0224
		mtu := declareUpBaseFlags(fs)
		resolve = func() error {
			if err := node.ValidateMTU(*mtu); err != nil {
				return err
			}
			if _, err := nf.resolve(); err != nil {
				return err
			}
			_, err := tf.resolve()
			return err
		}
	}
	var args []string
	if path != "" {
		args = []string{"--config", path}
	}
	if err := parseFlagsWithEnv(fs, args, allowed); err != nil {
		add(service.FindingError, describe(err))
		return out
	}
	if err := resolve(); err != nil {
		add(service.FindingError, describe(err))
		return out
	}
	if path != "" {
		add(service.FindingOK, fmt.Sprintf("%s geçerli ('%s' için)", path, command))
	}
	// Environment variables that look like ours but are not read.
	known := map[string]bool{envConfigFile: true}
	for _, list := range [][]string{upEnvFlags, coordinatorEnvFlags} {
		for _, f := range list {
			known[EnvName(f)] = true
		}
	}
	var set []string
	for _, kv := range environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(strings.ToUpper(name), envPrefix) {
			continue
		}
		if !known[strings.ToUpper(name)] {
			add(service.FindingWarn, name+" tanınmayan bir OpenScale ortam değişkeni; okunmuyor")
			continue
		}
		set = append(set, name)
	}
	if len(set) > 0 {
		slices.Sort(set)
		add(service.FindingInfo, "okunan ortam değişkenleri: "+strings.Join(set, ", "))
	}
	return out
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func cmdConfigtest(env *Env, args []string) error {
	fs := newFlagSet(env, "configtest")
	dataDir := fs.String("data-dir", "", "servisin veri klasörü (varsayılan: %ProgramData%\\OpenScale, Windows)")
	stateDir := fs.String("state-dir", "", "ön plan tünelinin veya koordinatörün durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	config := fs.String("config", "", "denetlenecek JSON yapılandırma dosyası ('up' veya 'coordinator run' için)")
	command := fs.String("for", "up", "yapılandırma dosyasının komutu: up veya coordinator")
	jsonOut := fs.Bool("json", false, "makine okunur JSON çıktı (\"schema\": 1)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cmdName := "up"
	switch *command {
	case "up":
	case "coordinator", "coordinator run":
		cmdName = "coordinator run"
	default:
		return usageError("--for up veya coordinator olmalı")
	}
	now := env.Now()
	var findings []service.Finding
	dd := *dataDir
	if dd == "" {
		dd = localAPI.dataDir()
	}
	if dd != "" {
		running := false
		if token, err := localAPI.readToken(dd); err == nil {
			c := &localClient{base: localAPI.serviceBase, token: token, service: true, http: newHTTPClient()}
			running = c.reachable(envContext(env))
		}
		findings = append(findings, service.CheckDataDir(dd, now, running, service.DefaultPanelPort)...)
	}
	if sd, err := resolveStateDir(env, *stateDir); err == nil {
		if _, statErr := os.Stat(sd); statErr == nil || *stateDir != "" {
			findings = append(findings, service.CheckStateDir(sd, now)...)
		}
	}
	findings = append(findings, checkUpConfig(env, cmdName, *config)...)
	if len(findings) == 0 {
		findings = append(findings, service.Finding{Level: service.FindingInfo, Area: "genel", Message: "denetlenecek bir OpenScale klasörü bulunamadı"})
	}
	errorsFound := 0
	for _, f := range findings {
		if f.Level == service.FindingError {
			errorsFound++
		}
	}
	if *jsonOut {
		if err := printJSON(env.Stdout, map[string]any{"schema": panel.DiagSchema, "ok": errorsFound == 0, "findings": findings}); err != nil {
			return err
		}
	} else {
		labels := map[string]string{service.FindingOK: "TAMAM", service.FindingInfo: "BİLGİ", service.FindingWarn: "UYARI", service.FindingError: "HATA"}
		for _, f := range findings {
			fmt.Fprintf(env.Stdout, "%-6s %-14s %s\n", labels[f.Level], f.Area, f.Message)
		}
	}
	if errorsFound > 0 {
		return fmt.Errorf("%d sorun bulundu", errorsFound)
	}
	if !*jsonOut {
		fmt.Fprintln(env.Stdout, "\nYapılandırma geçerli.")
	}
	return nil
}
