package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/msg"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
)

// P06 remote support commands (ADR-0146): session quality figures (#436),
// the session file browser (#435) and the help request (#424).

// rdeskTarget resolves the device and refuses early when the local copy of
// the rules already says no (the target decides in the end).
func rdeskTarget(env *Env, rf remoteFlags, target string, mode trust.RemoteDesktopMode) (remoteContext, string, netip.AddrPort, error) {
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(envContext(env), target)
	if err != nil {
		return rc, "", netip.AddrPort{}, err
	}
	if name == "" {
		name = addr.String()
	}
	if rc.doc != nil && rc.self != "" {
		if _, known := rc.doc.DeviceByName(name); known && !rc.doc.AllowsRemoteDesktop(rc.self, name, mode) {
			return rc, "", netip.AddrPort{}, fmt.Errorf("kurallar %s cihazından %s cihazına bu uzak masaüstü kipine izin vermiyor (rdesk kuralı gerekli)", rc.self, name)
		}
	}
	return rc, name, netip.AddrPortFrom(addr, trust.RemoteDesktopPort), nil
}

// peerPath asks the local service whether the tunnel to name is direct or
// relayed; "" when it cannot tell.
func peerPath(env *Env, stateDir, name string) string {
	c, err := openLocalClient(env, stateDir)
	if err != nil {
		return ""
	}
	var st panel.DiagStatus
	if err := c.get(env, "/status", &st); err != nil {
		return ""
	}
	for _, p := range st.Peers {
		if p.Name == name {
			switch p.Path {
			case panel.PathDirect:
				return "doğrudan"
			case panel.PathRelay:
				return "aktarıcı"
			}
			return "yok"
		}
	}
	return ""
}

// formatRDeskStats is one line of the quality overlay (#436).
func formatRDeskStats(st rdesk.Stats, path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%.1f kare/sn", st.FPS)
	if st.RTT > 0 {
		fmt.Fprintf(&b, ", gecikme %d ms", st.RTT.Milliseconds())
	} else {
		b.WriteString(", gecikme bilinmiyor")
	}
	fmt.Fprintf(&b, ", %s/sn", humanBytes(uint64(st.BytesPerSec)))
	if st.Width > 0 {
		fmt.Fprintf(&b, ", %d×%d ölçek 1/%d", st.Width, st.Height, max(st.Scale, 1))
	}
	if path != "" {
		fmt.Fprintf(&b, ", yol: %s", path)
	}
	return b.String()
}

func cmdRDeskStats(env *Env, args []string) error {
	fs := newFlagSet(env, "rdesk-stats")
	rf := addRemoteFlags(fs)
	monitor := fs.String("monitor", "primary", "monitör: primary, all veya 0'dan başlayan numara")
	duration := fs.Duration("duration", 30*time.Second, "ölçüm süresi (onaydan sonra)")
	interval := fs.Duration("interval", 2*time.Second, "satırlar arası süre")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale rdesk-stats <cihaz> [--duration 30s] [--interval 2s] [--monitor primary|all|N]")
		fmt.Fprintln(env.Stderr, "İzleme oturumu açar ve kare hızı, gecikme, bant genişliği ve yol türünü (doğrudan/aktarıcı) yazar; girdi göndermez.")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	mon, err := parseMonitorFlag(*monitor)
	if err != nil {
		return err
	}
	if *duration < time.Second || *duration > time.Hour {
		return usageError("--duration 1s ile 1h arasında olmalı")
	}
	if *interval < time.Second || *interval > time.Minute {
		return usageError("--interval 1s ile 1m arasında olmalı")
	}
	_, name, addr, err := rdeskTarget(env, rf, fs.Arg(0), trust.RemoteDesktopView)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	fmt.Fprintf(env.Stdout, "%s cihazına bağlanılıyor (yalnızca izleme); hedefte onay istenebilir...\n", name)
	c, err := rdesk.Dial(ctx, addr, rdesk.DialOptions{Mode: rdesk.ModeView, Monitor: mon})
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Fprintf(env.Stdout, "Doğrulama kodu: %s (hedefte görünenle aynı olmalı)\n", c.VerificationCode())
	if !c.Extended() {
		fmt.Fprintln(env.Stderr, "uyarı: hedef eski bir sürüm; gecikme ölçülemez")
	}
	end := time.NewTimer(*duration)
	defer end.Stop()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-end.C:
			return nil
		case <-tick.C:
		}
		if err := c.Err(); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, formatRDeskStats(c.Stats(), peerPath(env, *rf.stateDir, name)))
	}
}

func cmdRDeskFiles(env *Env, args []string) error {
	fs := newFlagSet(env, "rdesk-files")
	rf := addRemoteFlags(fs)
	path := fs.String("path", "", "listelenecek klasör: boş (sahibin seçtiği klasörler) veya kök/alt/klasör")
	get := fs.String("get", "", "çekilecek dosya: kök/alt/dosya")
	out := fs.String("out", "", "--get: yazılacak yeni yerel dosya")
	timeout := fs.Duration("timeout", rdeskTimeout, "hedefteki onay için en uzun bekleme")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale rdesk-files <cihaz> [--path kök/alt] | --get kök/alt/dosya --out dosya")
		fmt.Fprintln(env.Stderr, "Kontrol oturumu açar ve hedefin sahibinin seçtiği klasörlere göz atar veya dosya çeker; rdesk allow_control ve files kuralı gerekir.")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if (*get == "") != (*out == "") {
		return usageError("--get ve --out birlikte verilmeli")
	}
	if *get != "" && *path != "" {
		return usageError("--path ve --get birlikte kullanılamaz")
	}
	if *timeout < 5*time.Second || *timeout > 10*time.Minute {
		return usageError("--timeout 5s ile 10m arasında olmalı")
	}
	if *out != "" {
		if _, err := os.Lstat(*out); err == nil {
			return fmt.Errorf("%s zaten var; üzerine yazılmaz", *out)
		}
	}
	rc, name, addr, err := rdeskTarget(env, rf, fs.Arg(0), trust.RemoteDesktopControl)
	if err != nil {
		return err
	}
	if rc.doc != nil && rc.self != "" {
		if _, known := rc.doc.DeviceByName(name); known && !rc.doc.AllowsFileSend(rc.self, name) {
			return fmt.Errorf("kurallar %s cihazından %s cihazına files izni vermiyor", rc.self, name)
		}
	}
	ctx := envContext(env)
	fmt.Fprintf(env.Stdout, "%s cihazına bağlanılıyor (kontrol); hedefte onay istenebilir...\n", name)
	dctx, cancel := context.WithTimeout(ctx, *timeout)
	c, err := rdesk.Dial(dctx, addr, rdesk.DialOptions{Mode: rdesk.ModeControl, Monitor: rdesk.MonitorPrimary, MaxFPS: 2, Scale: 4})
	cancel()
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Fprintf(env.Stdout, "Doğrulama kodu: %s\n", c.VerificationCode())
	if *get == "" {
		ents, trunc, err := c.ListFiles(ctx, *path)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.Dir {
				fmt.Fprintf(env.Stdout, "%-40s  klasör\n", e.Name+"/")
				continue
			}
			fmt.Fprintf(env.Stdout, "%-40s  %10s  %s\n", e.Name, humanBytes(uint64(e.Size)), e.ModTime.Local().Format("2006-01-02 15:04"))
		}
		if trunc {
			fmt.Fprintln(env.Stdout, "(liste kısaltıldı; ilk 2000 öge)")
		}
		return nil
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%s oluşturulamadı: %w", *out, err)
	}
	n, err := c.FetchFile(ctx, *get, f, 0)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(*out)
		return err
	}
	fmt.Fprintf(env.Stdout, "%s (%s) %s dosyasına yazıldı; SHA-256 doğrulandı.\n", *get, humanBytes(uint64(n)), *out)
	return nil
}

// helpRequestText is the message the owner's devices receive (#424).
func helpRequestText(self, note string) string {
	t := fmt.Sprintf("Uzaktan yardım isteği: %s cihazındaki kişi yardım istiyor.", self)
	if note != "" {
		t += " Not: " + note
	}
	return t + fmt.Sprintf(" Bağlanmak için: openscale rdesk %s (hedefte yine onay sorulur).", self)
}

// helpTargets are the devices that may control self: the people who can
// help. Unattended access is never granted by a request.
func helpTargets(doc *trust.Document, self, only string, now time.Time) []trust.Device {
	var out []trust.Device
	for _, d := range doc.Devices {
		if d.Name == self || !activeDevice(d, now) || (only != "" && d.Name != only) {
			continue
		}
		if doc.AllowsRemoteDesktop(d.Name, self, trust.RemoteDesktopControl) {
			out = append(out, d)
		}
	}
	return out
}

func cmdRDeskHelp(env *Env, args []string) error {
	fs := newFlagSet(env, "rdesk-help")
	rf := addRemoteFlags(fs)
	to := fs.String("to", "", "yalnızca bu cihaza gönder (varsayılan: bu cihazı kontrol izni olan bütün cihazlar)")
	note := fs.String("note", "", "isteğe eklenecek kısa not")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(*note) > 500 {
		return usageError("--note en fazla 500 bayt olabilir")
	}
	mc, err := loadMsgContext(env, rf)
	if err != nil {
		return err
	}
	self, priv, err := mc.self(mc.rc.doc)
	if err != nil {
		return err
	}
	defer clear(priv)
	targets := helpTargets(mc.rc.doc, self.Name, *to, env.Now())
	if len(targets) == 0 {
		if *to != "" {
			return fmt.Errorf("%s bu cihazı uzaktan kontrol edemez (rdesk allow_control kuralı yok) veya etkin değil", *to)
		}
		return errors.New("bu cihazı uzaktan kontrol izni olan bir cihaz yok; ağ yöneticisi bir rdesk kuralı (allow_control) eklemeli")
	}
	text := helpRequestText(self.Name, msg.SafeText(*note))
	if err := msg.CheckText(text); err != nil {
		return usageError("%v", err)
	}
	ctx := envContext(env)
	sent := 0
	var errs []error
	for _, d := range targets {
		envl, err := msg.Seal(env.Random, priv, d.WireGuardKey[:], self.Name, d.Name, env.Now(), text)
		if err != nil {
			return err
		}
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = msg.Send(sctx, netip.AddrPortFrom(d.IPv4, msg.Port), envl)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Name, err))
			fmt.Fprintf(env.Stderr, "%s cihazına iletilemedi: %v\n", d.Name, err)
			continue
		}
		_ = mc.store.AddSent(msg.Message{ID: envl.ID, Peer: d.Name, At: time.Unix(envl.Time, 0), Text: text})
		fmt.Fprintf(env.Stdout, "Yardım isteği gönderildi: %s\n", d.Name)
		sent++
	}
	if sent == 0 {
		return fmt.Errorf("yardım isteği hiçbir cihaza ulaşmadı (alıcıda 'openscale msg listen' ve tcp/%d kuralı gerekir): %w", msg.Port, errors.Join(errs...))
	}
	fmt.Fprintln(env.Stdout, "Bağlanan kişi için bu bilgisayarda yine onay sorulacak; gözetimsiz erişim açılmadı.")
	return nil
}
