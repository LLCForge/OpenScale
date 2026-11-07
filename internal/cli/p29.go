package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/msg"
	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/privsep"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/stealth"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/winapp"
)

// P29 (ADR-0109): device posture, embedded messaging, low-visibility mode
// and the privilege report.

const msgDirName = "msg"

func p29Commands() []command {
	return []command{
		{"posture", "Cihaz duruşu: disk şifreleme, güvenlik duvarı, Windows derlemesi, Wi-Fi MAC (cihazın kendi ifadesi) [--require ...] [--json]", cmdPosture},
		{"msg send", "Bir cihaza tünel içinden uçtan uca şifreli mesaj gönderir: <cihaz> <metin>", cmdMsgSend},
		{"msg listen", "Mesajları tünel adresinde alır (tcp/4048; kural gerekir)", cmdMsgListen},
		{"msg list", "Bu cihazdaki mesajları gösterir [--peer cihaz] [--json]", cmdMsgList},
		{"msg delete", "Mesaj siler: <kimlik> | --all", cmdMsgDelete},
		{"stealth", "Düşük görünürlük modu (tepsi simgesi, bildirimler): on|off|status; korumalar asla kapanmaz", cmdStealth},
	}
}

// --- posture (#105, #155, #41) ---

type postureJSON struct {
	Schema         int      `json:"schema"`
	DiskEncryption string   `json:"disk_encryption"`
	Firewall       string   `json:"firewall"`
	WindowsBuild   int      `json:"windows_build,omitempty"`
	MACAdvice      []string `json:"mac_advice,omitempty"`
	Process        string   `json:"process"`
	Unmet          []string `json:"unmet,omitempty"`
	Note           string   `json:"note"`
}

func stateCode(s posture.State) string {
	switch s {
	case posture.On:
		return "on"
	case posture.Off:
		return "off"
	}
	return "unknown"
}

// parseRequirement reads "disk,firewall,build=26100".
func parseRequirement(s string) (posture.Requirement, error) {
	var q posture.Requirement
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case part == "disk":
			q.DiskEncryption = true
		case part == "firewall":
			q.Firewall = true
		case strings.HasPrefix(part, "build="):
			n, err := strconv.Atoi(strings.TrimPrefix(part, "build="))
			if err != nil || n <= 0 || n >= 1_000_000 {
				return q, usageError("geçersiz derleme numarası %q", part)
			}
			q.MinWindowsBuild = n
		default:
			return q, usageError("bilinmeyen koşul %q (disk, firewall, build=N)", part)
		}
	}
	return q, nil
}

func cmdPosture(env *Env, args []string) error {
	fs := newFlagSet(env, "posture")
	require := fs.String("require", "", "karşılanması istenen koşullar: disk,firewall,build=N (karşılanmazsa hata döner)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	q, err := parseRequirement(*require)
	if err != nil {
		return err
	}
	r := posture.Collect()
	advice := posture.MACAdvice(posture.WiFiInterfaces())
	unmet := posture.Evaluate(q, r)
	proc := privsep.CurrentStatus().Summary
	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(postureJSON{
			Schema: 1, DiskEncryption: stateCode(r.DiskEncryption), Firewall: stateCode(r.Firewall),
			WindowsBuild: r.WindowsBuild, MACAdvice: advice, Process: proc, Unmet: unmet, Note: posture.Disclaimer,
		}); err != nil {
			return err
		}
	} else {
		w := env.Stdout
		fmt.Fprintf(w, "Disk şifreleme:   %s\n", r.DiskEncryption)
		fmt.Fprintf(w, "Güvenlik duvarı:  %s\n", r.Firewall)
		if r.WindowsBuild > 0 {
			fmt.Fprintf(w, "Windows derlemesi: %d\n", r.WindowsBuild)
		}
		fmt.Fprintf(w, "Bu sürecin yetkisi: %s\n", proc)
		for _, a := range advice {
			fmt.Fprintf(w, "Uyarı: %s\n", a)
		}
		if r.DiskEncryption == posture.Unknown || r.Firewall == posture.Unknown {
			fmt.Fprintln(w, "Not: bazı denetimler yönetici/root yetkisi ister; yetki yoksa sonuç \"bilinmiyor\" olur.")
		}
		fmt.Fprintln(w, posture.Disclaimer)
		for _, u := range unmet {
			fmt.Fprintf(w, "Karşılanmayan koşul: %s\n", u)
		}
	}
	if len(unmet) > 0 {
		return fmt.Errorf("duruş koşulları karşılanmadı (%d)", len(unmet))
	}
	return nil
}

// warnCoordinatorDisk is the #155 check at coordinator start: the
// coordinator's disk holds its key and the membership store.
func warnCoordinatorDisk(env *Env) {
	if posture.DiskEncryption() == posture.Off {
		fmt.Fprintln(env.Stderr, "uyarı: sunucu diski şifreli görünmüyor; koordinatör anahtarı ve üyelik deposu diskte açık durur. LUKS/BitLocker ile şifreli bir disk önerilir (ADR-0109).")
	}
}

// warnExitNodeMAC is the #41 advice when traffic is sent through an
// exit node: the exit node hides traffic, not the Wi-Fi MAC address.
func warnExitNodeMAC(env *Env, exitNode string) {
	if strings.TrimSpace(exitNode) == "" {
		return
	}
	for _, a := range posture.MACAdvice(posture.WiFiInterfaces()) {
		fmt.Fprintf(env.Stderr, "uyarı: %s\n", a)
	}
}

// --- embedded messaging (#242) ---

// msgContext is what the message commands need: the signed document,
// this device's key file and the on-device message store.
type msgContext struct {
	rc      remoteContext
	keyPath string
	store   *msg.Store
}

func loadMsgContext(env *Env, rf remoteFlags) (msgContext, error) {
	rc := loadRemoteContext(env, rf)
	if rc.doc == nil || rc.base == "" {
		return msgContext{}, errors.New("ağ üyeliği okunamadı; Windows'ta yönetici olarak çalıştırın veya --state-dir verin")
	}
	mc := msgContext{rc: rc, store: msg.OpenStore(filepath.Join(rc.base, msgDirName))}
	for _, p := range []string{filepath.Join(rc.base, service.DeviceDir, deviceKeyFile), filepath.Join(rc.base, deviceKeyFile)} {
		if _, err := os.Stat(p); err == nil {
			mc.keyPath = p
			break
		}
	}
	if mc.keyPath == "" {
		return msgContext{}, errors.New("cihaz anahtarı bulunamadı")
	}
	return mc, nil
}

// self reads this device's key and finds it in doc. The key is read for
// each use so a rotation takes effect; the caller clears priv.
func (mc msgContext) self(doc *trust.Document) (trust.Device, []byte, error) {
	secrets, err := readSecrets(mc.keyPath)
	if err != nil {
		return trust.Device{}, nil, fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	dev, err := selfDevice(doc, secrets)
	if err != nil {
		return trust.Device{}, nil, err
	}
	priv := append([]byte(nil), secrets.WireGuardPrivate...)
	clear(secrets.WireGuardPrivate)
	return dev, priv, nil
}

func deviceNamed(doc *trust.Document, name string) (trust.Device, bool) {
	for _, d := range doc.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return trust.Device{}, false
}

func activeDevice(d trust.Device, now time.Time) bool {
	return !d.WireGuardKey.IsZero() && d.IPv4.IsValid() && (d.ExpiresAt.IsZero() || now.Before(d.ExpiresAt))
}

func cmdMsgSend(env *Env, args []string) error {
	fs := newFlagSet(env, "msg send")
	rf := addRemoteFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale msg send [seçenekler] <cihaz> <metin>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() < 2 {
		return usageError("cihaz ve metin gerekli: openscale msg send <cihaz> <metin>")
	}
	text := strings.Join(fs.Args()[1:], " ")
	if err := msg.CheckText(text); err != nil {
		return usageError("%v", err)
	}
	mc, err := loadMsgContext(env, rf)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	devName, _, err := mc.rc.resolveTarget(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	peer, ok := deviceNamed(mc.rc.doc, devName)
	if !ok || !activeDevice(peer, env.Now()) {
		// Messages go only to devices of the signed document, at their
		// tunnel address, with their document key.
		return fmt.Errorf("%q imzalı ağ belgesinde etkin bir cihaz değil", fs.Arg(0))
	}
	self, priv, err := mc.self(mc.rc.doc)
	if err != nil {
		return err
	}
	defer clear(priv)
	if self.Name == peer.Name {
		return usageError("kendinize mesaj gönderemezsiniz")
	}
	envl, err := msg.Seal(env.Random, priv, peer.WireGuardKey[:], self.Name, peer.Name, env.Now(), text)
	if err != nil {
		return err
	}
	if err := msg.Send(ctx, netip.AddrPortFrom(peer.IPv4, msg.Port), envl); err != nil {
		return err
	}
	if err := mc.store.AddSent(msg.Message{ID: envl.ID, Peer: peer.Name, At: time.Unix(envl.Time, 0), Text: text}); err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: mesaj gönderildi ama bu cihazda kaydedilemedi: %v\n", err)
	}
	fmt.Fprintf(env.Stdout, "Gönderildi: %s (%s)\n", peer.Name, envl.ID[:8])
	return nil
}

func cmdMsgListen(env *Env, args []string) error {
	fs := newFlagSet(env, "msg listen")
	rf := addRemoteFlags(fs)
	quiet := fs.Bool("quiet", false, "gelen mesajları ekrana yazma (yalnızca kaydet)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	mc, err := loadMsgContext(env, rf)
	if err != nil {
		return err
	}
	self, priv, err := mc.self(mc.rc.doc)
	clear(priv)
	if err != nil {
		return err
	}
	addr := netip.AddrPortFrom(self.IPv4, msg.Port)
	ctx := envContext(env)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp4", addr.String())
	if err != nil {
		return fmt.Errorf("tünel adresi dinlenemedi (tünel açık mı?): %w", err)
	}
	logger := newLogger(env, false)
	var doc atomic.Pointer[trust.Document]
	doc.Store(mc.rc.doc)
	srv, err := msg.NewServer(msg.ServerConfig{
		// The document is reloaded for every connection: a revoked sender
		// or a rotated key takes effect without a restart.
		PeerByAddr: func(a netip.Addr) (msg.Peer, bool) {
			if cur := loadRemoteContext(env, rf); cur.doc != nil {
				doc.Store(cur.doc)
			}
			d, ok := doc.Load().DeviceByAddr(a)
			if !ok || d.Name == self.Name || !activeDevice(d, env.Now()) {
				return msg.Peer{}, false
			}
			return msg.Peer{Name: d.Name, WireGuardPublic: append([]byte(nil), d.WireGuardKey[:]...)}, true
		},
		Self: func() (string, []byte, error) {
			d, p, err := mc.self(doc.Load())
			return d.Name, p, err
		},
		Store: mc.store,
		OnMessage: func(m msg.Message) {
			if !*quiet {
				fmt.Fprintf(env.Stdout, "[%s] %s: %s\n", m.At.Local().Format("2006-01-02 15:04"), m.Peer, msg.SafeText(m.Text))
			}
		},
		Logger: logger,
		Now:    env.Now,
	})
	if err != nil {
		_ = ln.Close()
		return err
	}
	fmt.Fprintf(env.Stdout, "Mesajlar %s üzerinde bekleniyor (yalnızca tünel içi). Durdurmak için Ctrl+C.\n", addr)
	fmt.Fprintf(env.Stdout, "Not: gönderen cihazdan bu cihaza tcp/%d için bir izin kuralı gerekir.\n", msg.Port)
	return srv.Serve(ctx, ln)
}

func cmdMsgList(env *Env, args []string) error {
	fs := newFlagSet(env, "msg list")
	rf := addRemoteFlags(fs)
	peer := fs.String("peer", "", "yalnızca bu cihazla olan mesajlar")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	rc := loadRemoteContext(env, rf)
	if rc.base == "" {
		return errors.New("durum klasörü bulunamadı; --state-dir veya --data-dir verin")
	}
	list, err := msg.OpenStore(filepath.Join(rc.base, msgDirName)).List(strings.TrimSpace(*peer))
	if err != nil {
		if errors.Is(err, iofs.ErrPermission) {
			return errors.New("mesaj deposu okunamadı; Windows'ta yönetici olarak çalıştırın")
		}
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Schema   int           `json:"schema"`
			Messages []msg.Message `json:"messages"`
		}{1, list})
	}
	if len(list) == 0 {
		fmt.Fprintln(env.Stdout, "Mesaj yok.")
		return nil
	}
	for _, m := range list {
		dir := "←"
		if m.Out {
			dir = "→"
		}
		fmt.Fprintf(env.Stdout, "%s  %s %s %s: %s\n", m.ID[:8], m.At.Local().Format("2006-01-02 15:04"), dir, m.Peer, msg.SafeText(m.Text))
	}
	return nil
}

func cmdMsgDelete(env *Env, args []string) error {
	fs := newFlagSet(env, "msg delete")
	rf := addRemoteFlags(fs)
	all := fs.Bool("all", false, "bütün mesajları sil")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	rc := loadRemoteContext(env, rf)
	if rc.base == "" {
		return errors.New("durum klasörü bulunamadı; --state-dir veya --data-dir verin")
	}
	store := msg.OpenStore(filepath.Join(rc.base, msgDirName))
	if *all {
		if fs.NArg() != 0 {
			return usageError("--all ile kimlik verilmez")
		}
		if err := store.Clear(); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Bütün mesajlar silindi.")
		return nil
	}
	if fs.NArg() != 1 {
		return usageError("silinecek mesajın kimliği gerekli (msg list ilk 8 karakteri gösterir)")
	}
	prefix := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	list, err := store.List("")
	if err != nil {
		return err
	}
	var match []string
	for _, m := range list {
		if len(prefix) >= 8 && strings.HasPrefix(m.ID, prefix) {
			match = append(match, m.ID)
		}
	}
	switch len(match) {
	case 0:
		return fmt.Errorf("%q kimlikli mesaj yok", prefix)
	case 1:
	default:
		return fmt.Errorf("%q birden çok mesajla eşleşiyor; daha uzun kimlik verin", prefix)
	}
	if _, err := store.Delete(match[0]); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Mesaj silindi.")
	return nil
}

// --- low-visibility mode (#247) ---

func cmdStealth(env *Env, args []string) error {
	fs := newFlagSet(env, "stealth")
	dataDir := fs.String("data-dir", "", "servisin veri klasörü (varsayılan: %ProgramData%\\OpenScale; yönetici gerekir)")
	tray := fs.Bool("tray", true, "on: tepsi simgesini gizle")
	notes := fs.Bool("notifications", true, "on: balon bildirimlerini kapat")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale stealth on|off|status [--tray=false] [--notifications=false] [--data-dir klasör]")
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		if err := parseFlags(fs, args); err != nil {
			return err
		}
		return usageError("on, off veya status yazın")
	}
	mode := args[0]
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	dir := *dataDir
	if dir == "" {
		dir = winapp.DataDir()
	}
	if dir == "" {
		return errors.New("düşük görünürlük modu masaüstü uygulaması içindir (Windows); --data-dir ile klasörü belirtin")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("veri klasörü bulunamadı: %s", dir)
	}
	w := env.Stdout
	switch mode {
	case "status":
		s, err := stealth.Load(dir)
		if err != nil {
			fmt.Fprintf(w, "Ayar dosyası geçersiz (%v); mod kapalı sayılıyor.\n", err)
			return nil
		}
		fmt.Fprintf(w, "Tepsi simgesi gizli: %s\nBildirimler kapalı: %s\n", yesNo(s.HideTray), yesNo(s.QuietNotifications))
	case "on":
		s := stealth.Settings{HideTray: *tray, QuietNotifications: *notes}
		if !s.Enabled() {
			return usageError("en az bir seçenek açık olmalı")
		}
		if err := stealth.Save(dir, s); err != nil {
			if errors.Is(err, iofs.ErrPermission) || errors.Is(err, securefile.ErrInsecurePermissions) {
				return errors.New("ayar yazılamadı; yönetici olarak çalıştırın")
			}
			return err
		}
		fmt.Fprintln(w, "Düşük görünürlük modu açıldı; masaüstü uygulaması yeniden başlayınca geçerli olur.")
		fmt.Fprintln(w, "Panel: openscale panel. Kapatmak için: openscale stealth off")
	case "off":
		if err := stealth.Save(dir, stealth.Settings{}); err != nil {
			return err
		}
		fmt.Fprintln(w, "Düşük görünürlük modu kapatıldı.")
	default:
		return usageError("on, off veya status yazın")
	}
	fmt.Fprintln(w, "Kill switch, sızıntı korumaları ve güvenlik duvarı kuralları bu moddan etkilenmez.")
	return nil
}
