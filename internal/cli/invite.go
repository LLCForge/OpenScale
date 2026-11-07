package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

const maxCodeFile = 8 << 10

// cmdInviteJoin joins a headless computer (for example a server) with an
// invite code. It prints the 4-digit code the owner approves in the panel
// and returns once approved (ADR-0014).
func cmdInviteJoin(env *Env, args []string) error {
	fs := newFlagSet(env, "invite-join")
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	codeArg := fs.String("code", "", "davet kodu veya @dosya (zorunlu)")
	name := fs.String("name", "", "önerilen cihaz adı (varsayılan: bilgisayar adı)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *codeArg == "" {
		return usageError("--code zorunlu")
	}
	line := *codeArg
	if path, ok := strings.CutPrefix(line, "@"); ok {
		data, err := securefile.ReadLimited(path, maxCodeFile)
		if err != nil {
			return fmt.Errorf("davet kodu okunamadı: %w", err)
		}
		line = string(data)
	}
	code, err := trust.DecodeInviteCode(line)
	if err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	secrets, _, err := loadOrCreateDeviceSecrets(env, filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return err
	}
	hostname := *name
	if hostname == "" {
		hostname, _ = env.Hostname()
	}
	fmt.Fprintln(env.Stdout, "Koordinatöre bağlanılıyor...")
	store, err := node.JoinWithInvite(envContext(env), node.InviteJoinConfig{
		Code:     code,
		Secrets:  secrets,
		Hostname: hostname,
		StateDir: dir,
		Logger:   newLogger(env, false),
		Now:      env.Now,
		OnWaiting: func(req *trust.EnrollmentRequest) {
			fmt.Fprintf(env.Stdout, "\nOnay kodu: %s\n", req.ShortCode())
			fmt.Fprintln(env.Stdout, "Yönetici panelinde Cihazlar > onay bekleyenler bölümünde aynı kodu görünce onayla.")
			fmt.Fprintln(env.Stdout, "Onay bekleniyor (Ctrl+C ile vazgeç)...")
		},
	})
	if err != nil {
		return err
	}
	doc := store.Document()
	self, err := selfDevice(doc, secrets)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "\nAğa katılındı: %s.%s  %s\n", self.Name, doc.DNSDomain, self.IPv4)
	fmt.Fprintf(env.Stdout, "Tüneli açmak için: openscale up --state-dir %s\n", dir)
	return nil
}
