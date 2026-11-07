package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/speedtest"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/winapp"
)

// Remote access and diagnostics commands (ADR-0030, ADR-0031): ssh, send,
// wake, speedtest and files. They run from this computer through the
// tunnel; the receiving device decides from the signed rules.

const (
	sshDialTimeout = 15 * time.Second
	knownHostsName = "known_hosts"
	maxKnownHosts  = 1 << 20
	resizePoll     = 500 * time.Millisecond
)

// exitCodeError carries a remote command's exit status to the process.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("uzak komut %d koduyla bitti", e.code) }

// remoteFlags are the flags every remote command shares.
type remoteFlags struct {
	dataDir  *string
	stateDir *string
}

func addRemoteFlags(fs *flag.FlagSet) remoteFlags {
	return remoteFlags{
		dataDir:  fs.String("data-dir", "", "masaüstü servisinin veri klasörü (varsayılan: %ProgramData%\\OpenScale; yönetici gerekir)"),
		stateDir: fs.String("state-dir", "", "'openscale up' durum klasörü (Linux ve sunucular)"),
	}
}

// remoteContext is what the commands know about the network here. doc is
// nil when the membership could not be read (for example without
// administrator rights on Windows); then targets must be IP addresses or
// full MagicDNS names.
type remoteContext struct {
	doc  *trust.Document
	self string
	// base is the data or state directory (apps state lives under it).
	base string
}

func loadRemoteContext(env *Env, f remoteFlags) remoteContext {
	var candidates []struct{ store, base string }
	switch {
	case *f.stateDir != "":
		candidates = append(candidates, struct{ store, base string }{*f.stateDir, *f.stateDir})
	case *f.dataDir != "":
		candidates = append(candidates, struct{ store, base string }{filepath.Join(*f.dataDir, service.DeviceDir), *f.dataDir})
	default:
		if d := winapp.DataDir(); d != "" {
			candidates = append(candidates, struct{ store, base string }{filepath.Join(d, service.DeviceDir), d})
		}
		if env.DefaultStateDir != nil {
			if d, err := env.DefaultStateDir(); err == nil {
				candidates = append(candidates, struct{ store, base string }{d, d})
			}
		}
	}
	for _, c := range candidates {
		store, err := member.Open(c.store)
		if err != nil {
			continue
		}
		rc := remoteContext{doc: store.Document(), base: c.base}
		rc.self = localDevice(rc.doc)
		return rc
	}
	rc := remoteContext{}
	if len(candidates) > 0 {
		rc.base = candidates[0].base
	}
	return rc
}

// localDevice finds this computer in doc by its tunnel addresses.
func localDevice(doc *trust.Document) string {
	if doc == nil {
		return ""
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		if d, ok := doc.DeviceByAddr(ip.Unmap()); ok {
			return d.Name
		}
	}
	return ""
}

// resolveTarget turns a device name, MagicDNS name or tunnel IP into a
// device name (when known) and its tunnel IPv4 address.
func (rc remoteContext) resolveTarget(ctx context.Context, target string) (string, netip.Addr, error) {
	target = strings.TrimSpace(strings.TrimSuffix(target, "."))
	if target == "" {
		return "", netip.Addr{}, usageError("cihaz belirtilmeli")
	}
	if a, err := netip.ParseAddr(target); err == nil {
		name := ""
		if rc.doc != nil {
			if d, ok := rc.doc.DeviceByAddr(a); ok {
				name = d.Name
				a = d.IPv4
			}
		}
		return name, a.Unmap(), nil
	}
	lower := strings.ToLower(target)
	if rc.doc != nil {
		name := strings.TrimSuffix(lower, "."+rc.doc.DNSDomain)
		if d, ok := rc.doc.DeviceByName(name); ok {
			return d.Name, d.IPv4, nil
		}
		if !strings.Contains(name, ".") {
			return "", netip.Addr{}, deviceNotFound(rc.doc, name) // #798
		}
	}
	if strings.Contains(lower, ".") {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip4", lower)
		if err != nil || len(ips) == 0 {
			return "", netip.Addr{}, fmt.Errorf("%s çözülemedi: %v", lower, err)
		}
		name, _, _ := strings.Cut(lower, ".")
		return name, ips[0].Unmap(), nil
	}
	return "", netip.Addr{}, errors.New("ağ belgesi okunamadı; cihazın tam adını (cihaz.alan-adı) veya tünel IP adresini yazın ya da komutu yönetici olarak çalıştırın")
}

// --- ssh ---

func cmdSSH(env *Env, args []string) error {
	fs := newFlagSet(env, "ssh")
	rf := addRemoteFlags(fs)
	userFlag := fs.String("user", "", "uzak kullanıcı (varsayılan: bu bilgisayardaki kullanıcı adı; Windows cihazlarda 'system')")
	fingerprint := fs.String("fingerprint", "", "ilk bağlantıda beklenen host anahtarı parmak izi (SHA256:...), panelde cihaz ayrıntısında görünür")
	knownHosts := fs.String("known-hosts", "", "bilinen host anahtarları dosyası (varsayılan: kullanıcı yapılandırma klasörü)")
	tty := fs.Bool("t", false, "komut verilse bile terminal (PTY) iste")
	port := fs.Int("port", int(trust.SSHPort), "gömülü SSH sunucusunun tünel içi portu")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale ssh [seçenekler] [kullanıcı@]<cihaz> [komut...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() < 1 {
		return usageError("cihaz belirtilmeli: openscale ssh [kullanıcı@]<cihaz> [komut]")
	}
	if *port < 1 || *port > 65535 {
		return usageError("--port 1 ile 65535 arasında olmalı")
	}
	target := fs.Arg(0)
	remoteUser := *userFlag
	if u, host, ok := strings.Cut(target, "@"); ok {
		remoteUser, target = u, host
	}
	if remoteUser == "" {
		remoteUser = defaultRemoteUser()
	}
	command := strings.Join(fs.Args()[1:], " ")
	ctx := envContext(env)
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	hostID := name
	if hostID == "" {
		hostID = addr.String()
	}
	khPath := *knownHosts
	if khPath == "" {
		if khPath, err = defaultKnownHosts(); err != nil {
			return err
		}
	}
	cfg := &ssh.ClientConfig{
		User:              remoteUser,
		HostKeyCallback:   verifyHostKey(env, khPath, hostID, *fingerprint),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           sshDialTimeout,
	}
	d := net.Dialer{Timeout: sshDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(*port)).String())
	if err != nil {
		return fmt.Errorf("cihaza bağlanılamadı (kural ve tünel açık mı?): %w", err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, hostID, cfg)
	if err != nil {
		_ = conn.Close()
		if strings.Contains(err.Error(), "unable to authenticate") {
			return fmt.Errorf("giriş reddedildi: %s kullanıcısı için bu cihazdan bir ssh kuralı yok (Windows cihazlarda kullanıcı 'system' olmalı)", remoteUser)
		}
		return err
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	return runSSHSession(env, sess, command, *tty)
}

func defaultRemoteUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}

func runSSHSession(env *Env, sess *ssh.Session, command string, forceTTY bool) error {
	stdin, stdinIsFile := env.Stdin.(*os.File)
	stdout, stdoutIsFile := env.Stdout.(*os.File)
	interactive := stdinIsFile && term.IsTerminal(int(stdin.Fd())) && (command == "" || forceTTY)
	sess.Stdin, sess.Stdout, sess.Stderr = env.Stdin, env.Stdout, env.Stderr
	if interactive {
		w, h := 80, 24
		if stdoutIsFile {
			if cw, ch, err := term.GetSize(int(stdout.Fd())); err == nil {
				w, h = cw, ch
			}
		}
		termName := os.Getenv("TERM")
		if termName == "" {
			termName = "xterm-256color"
		}
		modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if err := sess.RequestPty(termName, h, w, modes); err != nil {
			return fmt.Errorf("terminal açılamadı: %w", err)
		}
		state, err := term.MakeRaw(int(stdin.Fd()))
		if err != nil {
			return fmt.Errorf("terminal ham kipe alınamadı: %w", err)
		}
		defer term.Restore(int(stdin.Fd()), state)
		restoreOut := enableVirtualTerminal(stdout)
		defer restoreOut()
		done := make(chan struct{})
		defer close(done)
		if stdoutIsFile {
			go watchResize(sess, stdout, w, h, done)
		}
	}
	var err error
	if command == "" {
		if err = sess.Shell(); err == nil {
			err = sess.Wait()
		}
	} else {
		err = sess.Run(command)
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		if ee.ExitStatus() == 0 {
			return nil
		}
		return exitCodeError{code: ee.ExitStatus()}
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		return nil
	}
	return err
}

// watchResize polls the terminal size (portable: Windows has no SIGWINCH)
// and tells the server when it changes.
func watchResize(sess *ssh.Session, out *os.File, w, h int, done <-chan struct{}) {
	t := time.NewTicker(resizePoll)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			cw, ch, err := term.GetSize(int(out.Fd()))
			if err != nil || (cw == w && ch == h) {
				continue
			}
			w, h = cw, ch
			_ = sess.WindowChange(h, w)
		}
	}
}

func defaultKnownHosts() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("kullanıcı yapılandırma klasörü bulunamadı; --known-hosts kullanın: %w", err)
	}
	return filepath.Join(dir, "OpenScale", knownHostsName), nil
}

// knownHost reads the stored host key for id ("" when none).
func knownHost(path, id string) (ssh.PublicKey, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxKnownHosts))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 || fields[0] != id {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			continue
		}
		key, err := ssh.ParsePublicKey(raw)
		if err != nil || key.Type() != fields[1] {
			continue
		}
		return key, nil
	}
	return nil, sc.Err()
}

// rememberHost stores id's host key, replacing an older line for id.
func rememberHost(path, id string, key ssh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var kept []string
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] == id {
				continue
			}
			kept = append(kept, strings.TrimSpace(line))
		}
	}
	kept = append(kept, fmt.Sprintf("%s %s %s", id, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal())))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "SHA256:") {
		s = "SHA256:" + s
	}
	return strings.TrimRight(s, "=")
}

// verifyHostKey checks the server's host key against the known hosts file
// (F-211). The first connection needs the fingerprint the panel shows: as
// --fingerprint or confirmed at the terminal.
func verifyHostKey(env *Env, path, id, expect string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		stored, err := knownHost(path, id)
		if err != nil {
			return fmt.Errorf("bilinen host anahtarları okunamadı: %w", err)
		}
		if stored != nil {
			if bytes.Equal(stored.Marshal(), key.Marshal()) {
				return nil
			}
			return fmt.Errorf("UYARI: %s cihazının SSH host anahtarı değişti (yeni parmak izi %s). "+
				"Cihaz yeniden kurulmadıysa bu bir saldırı olabilir. Paneldeki parmak iziyle doğrulayın; "+
				"doğruysa %s dosyasındaki %q satırını silip yeniden bağlanın", id, fp, path, id)
		}
		switch {
		case expect != "":
			if normalizeFingerprint(expect) != strings.TrimRight(fp, "=") {
				return fmt.Errorf("host anahtarı parmak izi eşleşmiyor: beklenen %s, gelen %s", expect, fp)
			}
		case env.IsTerminal != nil && env.IsTerminal() && env.ReadLine != nil:
			fmt.Fprintf(env.Stderr, "%s cihazına ilk bağlantı. SSH host anahtarı parmak izi:\n  %s\n", id, fp)
			fmt.Fprintln(env.Stderr, "Bunu paneldeki cihaz ayrıntısında (SSH host anahtarı) görünen parmak iziyle karşılaştırın.")
			ans, err := env.ReadLine("Aynı mı? (evet/hayır): ")
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(ans)) {
			case "evet", "e", "yes", "y":
			default:
				return errors.New("host anahtarı onaylanmadı; bağlantı kesildi")
			}
		default:
			return fmt.Errorf("ilk bağlantıda host anahtarı doğrulanmalı: --fingerprint %s (paneldeki değerle aynıysa)", fp)
		}
		if err := rememberHost(path, id, key); err != nil {
			return fmt.Errorf("host anahtarı kaydedilemedi: %w", err)
		}
		return nil
	}
}

// --- send ---

func cmdSend(env *Env, args []string) error {
	fs := newFlagSet(env, "send")
	rf := addRemoteFlags(fs)
	name := fs.String("name", "", "alıcıda kullanılacak dosya adı (varsayılan: dosyanın adı)")
	strip := fs.String("strip-metadata", "", "görüntü üst verisini gönderimden önce temizle: konum (GPS, XMP, IPTC) veya hepsi (bütün EXIF); temizlenemeyen biçim gönderilmez")
	wait := fs.Bool("wait", false, "alıcı çevrimdışıysa çevrimiçi olana kadar bekle ve öyle gönder (en çok 7 gün; dosya değişirse gönderilmez)")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale send [seçenekler] <dosya> <cihaz>")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 2); err != nil {
		return err
	}
	path, target := fs.Arg(0), fs.Arg(1)
	mode, err := sendStripMode(*strip)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	rc := loadRemoteContext(env, rf)
	devName, addr, err := rc.resolveTarget(ctx, target)
	if err != nil {
		return err
	}
	if devName == "" {
		devName = addr.String()
	}
	if *wait {
		return sendQueued(env, ctx, *rf.stateDir, devName, netip.AddrPortFrom(addr, trust.FilesPort), path, *name, mode)
	}
	fmt.Fprintf(env.Stdout, "%s cihazına gönderiliyor; alıcının kabul etmesi bekleniyor...\n", devName)
	last := time.Time{}
	res, err := filesend.SendWithoutMetadata(ctx, netip.AddrPortFrom(addr, trust.FilesPort), path, mode, &filesend.SendOptions{
		Name:    *name,
		TempDir: sendTempDir(env, *rf.stateDir),
		Progress: func(done, total int64) {
			if now := time.Now(); now.Sub(last) >= 500*time.Millisecond || done == total {
				last = now
				pct := int64(100)
				if total > 0 {
					pct = done * 100 / total
				}
				fmt.Fprintf(env.Stderr, "\r%s / %s (%%%d)", formatBytes(done), formatBytes(total), pct)
			}
		},
	})
	fmt.Fprintln(env.Stderr)
	if err != nil {
		if errors.Is(err, filesend.ErrRejected) {
			return errors.New("alıcı dosyayı kabul etmedi (kural yok, reddedildi veya süre doldu)")
		}
		return err
	}
	if res.Resumed > 0 {
		fmt.Fprintf(env.Stdout, "Önceki yarım aktarım sürdürüldü (%s zaten vardı).\n", formatBytes(res.Resumed))
	}
	fmt.Fprintf(env.Stdout, "Gönderildi: alıcıda %q olarak kaydedildi.\n", res.SavedName)
	return nil
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// parseFlagsWithArgs parses flags and requires exactly n positional
// arguments, which may come before or after the flags.
func parseFlagsWithArgs(fs *flag.FlagSet, args []string, n int) error {
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && i+1 < len(args) && !isBoolFlag(fs, name) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	if err := fs.Parse(append(append(flags, "--"), positional...)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() != n {
		return usageError("%d argüman bekleniyordu, %d verildi", n, fs.NArg())
	}
	return nil
}

func isBoolFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return name == "h" || name == "help"
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// --- speedtest ---

func cmdSpeedtest(env *Env, args []string) error {
	fs := newFlagSet(env, "speedtest")
	rf := addRemoteFlags(fs)
	upload := fs.Bool("upload", false, "yükleme hızını ölç (varsayılan: indirme)")
	dur := fs.Duration("sure", speedtest.DefaultDuration, "test süresi (100ms-10s)")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale speedtest <cihaz> [--upload] [--sure 5s]")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if *dur < 100*time.Millisecond || *dur > 10*time.Second {
		return usageError("--sure 100ms ile 10s arasında olmalı")
	}
	ctx := envContext(env)
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if name == "" {
		name = addr.String()
	}
	dir := speedtest.Download
	if *upload {
		dir = speedtest.Upload
	}
	fmt.Fprintf(env.Stdout, "%s ile %s testi (%s)...\n", name, dir, dur.String())
	res, err := speedtest.Run(ctx, netip.AddrPortFrom(addr, trust.SpeedtestPort), dir, *dur)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s: %.1f Mbit/s (%s, %.1f s)\n", dir, res.Mbps(), formatBytes(res.Bytes), res.Elapsed.Seconds())
	return nil
}

// --- wake ---

func cmdWake(env *Env, args []string) error {
	fs := newFlagSet(env, "wake")
	rf := addRemoteFlags(fs)
	mac := fs.String("mac", "", "uyandırılacak cihazın MAC adresi (varsayılan: servisin öğrendiği adres)")
	relay := fs.String("relay", "", "isteği iletecek aracı cihaz (varsayılan: kurallardaki aracılar sırayla)")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale wake <cihaz> [--mac aa:bb:cc:dd:ee:ff] [--relay cihaz]")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	ctx := envContext(env)
	rc := loadRemoteContext(env, rf)
	if rc.doc == nil || rc.self == "" {
		return errors.New("ağ belgesi okunamadı veya bu bilgisayar tünelde değil; komutu yönetici olarak çalıştırın (veya --state-dir verin) ve tünelin açık olduğundan emin olun")
	}
	target, _, err := rc.resolveTarget(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	relays := rc.doc.WakeRelays(rc.self, target)
	if *relay != "" {
		r := strings.ToLower(strings.TrimSpace(*relay))
		if !rc.doc.AllowsWake(rc.self, target, r) {
			return fmt.Errorf("%s bu cihaz için aracı olamaz: wake kuralının via listesinde değil", r)
		}
		relays = []string{r}
	}
	if len(relays) == 0 {
		return fmt.Errorf("%s cihazını uyandırmaya izin veren bir wake kuralı yok (kural: --service wake --via <aracı>)", target)
	}
	m := strings.TrimSpace(*mac)
	if m == "" {
		macs, _ := service.LoadWakeMACs(rc.base)
		m = service.WakeMACFor(macs, target)
	}
	if m == "" {
		return fmt.Errorf("%s cihazının MAC adresi bilinmiyor; --mac ile verin (panelde cihaz ayrıntısında da görünür)", target)
	}
	res, err := service.WakeVia(ctx, rc.doc, rc.self, target, m, relays, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Uyandırma paketi %s üzerinden gönderildi (%s). Cihazın açılması bir dakika sürebilir.\n", res.Relay, res.MAC)
	return nil
}

// --- files ---

func cmdFiles(env *Env, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usageError("alt komut gerekli: openscale files list|accept <no>|reject <no>|delete <ad>|auto <cihaz> on|off")
	}
	sub, rest := args[0], args[1:]
	fs := newFlagSet(env, "files "+sub)
	rf := addRemoteFlags(fs)
	want := map[string]int{"list": 0, "accept": 1, "reject": 1, "delete": 1, "auto": 2}
	n, ok := want[sub]
	if !ok {
		return usageError("bilinmeyen alt komut %q", sub)
	}
	if err := parseFlagsWithArgs(fs, rest, n); err != nil {
		return err
	}
	base := *rf.stateDir
	if base == "" {
		base = *rf.dataDir
	}
	if base == "" {
		base = winapp.DataDir()
	}
	if base == "" && env.DefaultStateDir != nil {
		if d, err := env.DefaultStateDir(); err == nil {
			base = d
		}
	}
	if base == "" {
		return usageError("--data-dir veya --state-dir gerekli")
	}
	w := env.Stdout
	switch sub {
	case "list":
		view, viaService := filesFromService(env, base)
		if !viaService {
			files, err := service.ListInbox(base)
			if err != nil {
				return permissionHint(err)
			}
			view.Files = files
			view.AutoAccept, _ = service.LoadAutoAccept(base)
		}
		if len(view.Pending) > 0 {
			fmt.Fprintln(w, "Bekleyen teklifler (kabul: openscale files accept <no>):")
			for _, p := range view.Pending {
				fmt.Fprintf(w, "  %s  %s -> %s (%s)\n", p.ID, p.From, p.Name, formatBytes(p.Size))
			}
		}
		if len(view.Files) == 0 {
			fmt.Fprintf(w, "Gelen kutusu boş (%s).\n", filepath.Join(base, service.InboxDir))
		} else {
			fmt.Fprintf(w, "Gelen kutusu (%s):\n", filepath.Join(base, service.InboxDir))
			for _, f := range view.Files {
				warn := ""
				if f.Executable {
					warn = "  [UYARI: çalıştırılabilir]"
				}
				from := f.From
				if from == "" {
					from = "?"
				}
				fmt.Fprintf(w, "  %-40s %10s  %s  %s%s\n", f.Name, formatBytes(f.Size), from, f.ReceivedAt.Local().Format("2006-01-02 15:04"), warn)
			}
		}
		if len(view.AutoAccept) > 0 {
			fmt.Fprintf(w, "Otomatik kabul: %s\n", strings.Join(view.AutoAccept, ", "))
		}
		return nil
	case "accept", "reject":
		if err := decideViaService(env, base, fs.Arg(0), sub == "accept"); err != nil {
			return err
		}
		if sub == "accept" {
			fmt.Fprintln(w, "Teklif kabul edildi; aktarım başlıyor.")
		} else {
			fmt.Fprintln(w, "Teklif reddedildi.")
		}
		return nil
	case "delete":
		if err := service.DeleteInboxFile(base, fs.Arg(0)); err != nil {
			return permissionHint(err)
		}
		fmt.Fprintln(w, "Dosya silindi.")
		return nil
	case "auto":
		on := strings.ToLower(fs.Arg(1))
		if on != "on" && on != "off" {
			return usageError("on veya off yazın")
		}
		if err := service.SetAutoAccept(base, fs.Arg(0), on == "on"); err != nil {
			return permissionHint(err)
		}
		if on == "on" {
			fmt.Fprintf(w, "%s cihazından gelen dosyalar sorulmadan kabul edilecek (kural yine gerekir).\n", fs.Arg(0))
		} else {
			fmt.Fprintf(w, "%s cihazından gelen dosyalar yeniden onay bekleyecek.\n", fs.Arg(0))
		}
		return nil
	}
	return nil
}

func permissionHint(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("veri klasörüne erişilemedi; komutu yönetici olarak çalıştırın: %w", err)
	}
	return err
}

// serviceRequest calls the desktop service's command line endpoints with
// the app token (readable only by administrators).
func serviceRequest(env *Env, base, method, path string, body any, out any) error {
	token, err := service.ReadToken(base)
	if err != nil {
		return permissionHint(fmt.Errorf("servis anahtarı okunamadı: %w", err))
	}
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(envContext(env), 10*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", service.DefaultPanelPort, path)
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("servise ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("servis %d döndürdü", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func filesFromService(env *Env, base string) (panel.InboxView, bool) {
	if runtime.GOOS != "windows" {
		return panel.InboxView{}, false
	}
	var v panel.InboxView
	if err := serviceRequest(env, base, http.MethodGet, "/api/app/cli/inbox", nil, &v); err != nil {
		return panel.InboxView{}, false
	}
	return v, true
}

func decideViaService(env *Env, base, id string, accept bool) error {
	if runtime.GOOS != "windows" {
		return errors.New("bekleyen teklifler yalnızca masaüstü servisinde var; 'openscale up' çalışan cihazlarda 'openscale files auto <cihaz> on' kullanın")
	}
	return serviceRequest(env, base, http.MethodPost, "/api/app/cli/inbox/decide", map[string]any{"id": id, "accept": accept}, nil)
}

// startUpApps runs the services next to "openscale up". Without a panel,
// file offers are accepted only from devices on the auto-accept list
// ("openscale files auto <cihaz> on --state-dir ...").
func startUpApps(ctx context.Context, dir string, engine service.AppEngine, iface string, logger *slog.Logger) func() {
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	apps := service.NewApps(service.AppsConfig{
		Dir:             dir,
		Engine:          func() service.AppEngine { return engine },
		TunnelInterface: func() string { return iface },
		Logger:          logger.With("role", "apps"),
	})
	go func() {
		defer close(done)
		apps.Run(actx)
	}()
	return func() {
		cancel()
		<-done
	}
}
