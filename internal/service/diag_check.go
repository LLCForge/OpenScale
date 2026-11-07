package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Configuration check (F-204): every problem of a data directory in one
// pass, without changing anything.

// Finding levels.
const (
	FindingOK    = "ok"
	FindingInfo  = "info"
	FindingWarn  = "warn"
	FindingError = "error"
)

// Finding is one result of a configuration check.
type Finding struct {
	Level   string `json:"level"`
	Area    string `json:"area"`
	Message string `json:"message"`
}

// documentWarnBefore: a document or membership ending sooner is a warning.
const documentWarnBefore = 7 * 24 * time.Hour

type checker struct {
	out []Finding
	now time.Time
}

func (c *checker) add(level, area, format string, args ...any) {
	c.out = append(c.out, Finding{Level: level, Area: area, Message: fmt.Sprintf(format, args...)})
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// readProblem explains why a private file could not be read.
func readProblem(err error) string {
	switch {
	case errors.Is(err, securefile.ErrInsecurePermissions):
		return "izinleri fazla açık; yalnızca sahibi okuyabilmeli (chmod 600)"
	case errors.Is(err, fs.ErrPermission):
		return "okuma izni yok; yönetici/root olarak çalıştırın"
	case errors.Is(err, fs.ErrNotExist):
		return "yok"
	}
	return err.Error()
}

// checkKey reads a key file and reports its public key's fingerprint.
func (c *checker) checkKey(area, path string) *trust.DeviceSecrets {
	s, err := readSecrets(path)
	if err != nil {
		c.add(FindingError, area, "%s: %s", filepath.Base(path), readProblem(err))
		return nil
	}
	c.add(FindingOK, area, "%s okunabiliyor ve yalnızca sahibine açık", filepath.Base(path))
	return s
}

// checkDocument checks a member's verified document.
func (c *checker) checkDocument(area string, doc *trust.Document) {
	c.add(FindingOK, area, "ağ belgesi imzası geçerli (sürüm %d)", doc.Version)
	switch left := doc.ExpiresAt.Sub(c.now); {
	case left <= 0:
		c.add(FindingError, area, "ağ belgesinin süresi %s tarihinde dolmuş; yönetici 'openscale network renew' çalıştırmalı", doc.ExpiresAt.Format("02.01.2006"))
	case left <= documentWarnBefore:
		c.add(FindingWarn, area, "ağ belgesinin süresi %d gün içinde doluyor", int(left.Hours()/24))
	}
	if doc.Coordinator == nil {
		c.add(FindingError, area, "belgede koordinatör yok; yönetici 'openscale network set-coordinator' çalıştırmalı")
	}
	if doc.IssuedAt.After(c.now.Add(clockSkewLimit)) {
		c.add(FindingWarn, area, "bu bilgisayarın saati geride görünüyor: belge gelecekte imzalanmış")
	}
}

// checkMember checks a member state directory with its key file.
func (c *checker) checkMember(area, dir, keyFile string) {
	if !exists(filepath.Join(dir, "anchor.json")) {
		c.add(FindingInfo, area, "bu klasör bir ağa katılmamış: %s", dir)
		return
	}
	store, err := member.Open(dir)
	if err != nil {
		if errors.Is(err, member.ErrNotJoined) {
			c.add(FindingError, area, "anchor.json okunamadı (izinleri veya içeriği bozuk)")
			return
		}
		c.add(FindingError, area, "durum dosyaları okunamadı: %v", err)
		return
	}
	doc := store.Document()
	c.checkDocument(area, doc)
	secrets := c.checkKey(area, filepath.Join(dir, keyFile))
	if secrets == nil {
		return
	}
	_, wg, err := secrets.PublicKeys()
	if err != nil {
		c.add(FindingError, area, "anahtar dosyası bozuk")
		return
	}
	if keyFile == coordKeyFile {
		if doc.Coordinator != nil && doc.Coordinator.WireGuardKey != wg {
			c.add(FindingWarn, area, "bu koordinatör anahtarı belgedeki koordinatör değil (devir sürüyor olabilir)")
		}
		return
	}
	self, err := selfDevice(doc, secrets)
	if err != nil {
		c.add(FindingError, area, "bu cihaz belgede yok: iptal edilmiş veya henüz eklenmemiş")
		return
	}
	c.add(FindingOK, area, "bu cihaz belgede kayıtlı: %s (%s)", self.Name, self.IPv4)
	if exp := self.ExpiresAt; !exp.IsZero() {
		switch left := exp.Sub(c.now); {
		case left <= 0:
			c.add(FindingError, area, "bu cihazın üyeliği %s tarihinde bitmiş", exp.Format("02.01.2006"))
		case left <= documentWarnBefore:
			c.add(FindingWarn, area, "bu cihazın üyeliği %d gün içinde bitiyor", int(left.Hours()/24))
		}
	}
}

// checkSettings reads settings.json strictly (unknown fields are only a
// warning: a newer version may have written them) and checks its values.
func (c *checker) checkSettings(dir string) (settings, bool) {
	path := filepath.Join(dir, settingsFile)
	data, err := securefile.ReadPrivate(path, maxSettingsSize)
	if errors.Is(err, fs.ErrNotExist) {
		c.add(FindingOK, "ayarlar", "settings.json yok; varsayılanlar kullanılıyor")
		return settings{}, true
	}
	if err != nil {
		c.add(FindingError, "ayarlar", "settings.json: %s", readProblem(err))
		return settings{}, false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var strict settings
	if err := dec.Decode(&strict); err != nil {
		var syntax *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &syntax) || errors.As(err, &typeErr) {
			c.add(FindingError, "ayarlar", "settings.json bozuk: %v", err)
			return settings{}, false
		}
		c.add(FindingWarn, "ayarlar", "settings.json bu sürümün tanımadığı bir alan içeriyor (yeni sürümden kalmış olabilir): %v", err)
	}
	st, err := loadSettings(dir)
	if err != nil {
		c.add(FindingError, "ayarlar", "settings.json okunamadı: %v", err)
		return settings{}, false
	}
	ok := true
	if st.MTU != 0 {
		if err := node.ValidateMTU(st.MTU); err != nil {
			c.add(FindingWarn, "ayarlar", "mtu: %v (varsayılan kullanılacak)", err)
			ok = false
		}
	}
	if st.ForceRelay && st.MTU > node.DefaultMTU {
		c.add(FindingWarn, "ayarlar", "aktarıcı zorunluyken MTU en fazla %d olabilir", node.DefaultMTU)
		ok = false
	}
	if err := validRelayLimits(st.CoordinatorRelayRate, st.CoordinatorRelayBurst); err != nil {
		c.add(FindingWarn, "ayarlar", "%v (varsayılanlar kullanılacak)", err)
		ok = false
	}
	if err := st.tunnel().validate(); err != nil {
		c.add(FindingWarn, "ayarlar", "bağlantı tercihi kullanılamaz: %v", err)
		ok = false
	}
	if ok {
		c.add(FindingOK, "ayarlar", "settings.json geçerli")
	}
	return st, true
}

// probePorts tries to bind the service's ports on loopback. Binding only
// 127.0.0.1 never prompts a firewall; a program holding the port on every
// address is still found on most systems.
func (c *checker) probePorts(st settings, panelPort int) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(panelPort)))
	if err != nil {
		c.add(FindingError, "portlar", "panel portu %d/tcp başka bir program tarafından kullanılıyor", panelPort)
	} else {
		_ = ln.Close()
		c.add(FindingOK, "portlar", "panel portu %d/tcp boş", panelPort)
	}
	if st.CoordinatorPort > 0 {
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(st.CoordinatorPort)))
		if err != nil {
			c.add(FindingError, "portlar", "koordinatör portu %d/udp kullanımda veya ayrılmış (Hyper-V/WSL aralığı olabilir)", st.CoordinatorPort)
		} else {
			_ = pc.Close()
			c.add(FindingOK, "portlar", "koordinatör portu %d/udp boş", st.CoordinatorPort)
		}
	}
}

// CheckDataDir checks the desktop service's data directory. With
// serviceRunning the ports are known to be the service's own and are not
// probed.
func CheckDataDir(dir string, now time.Time, serviceRunning bool, panelPort int) []Finding {
	c := &checker{now: now}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		c.add(FindingInfo, "veri klasörü", "servis veri klasörü yok: %s", dir)
		return c.out
	}
	st, _ := c.checkSettings(dir)
	if exists(filepath.Join(dir, NetworkDir, "root.key")) {
		if n, err := admin.Load(filepath.Join(dir, NetworkDir), admin.Options{}); err != nil {
			c.add(FindingError, "ağ (yönetici)", "ağ klasörü okunamadı: %v", err)
		} else if doc, err := n.Document(); err == nil {
			c.add(FindingOK, "ağ (yönetici)", "kök anahtar ve belge geçerli (sürüm %d)", doc.Version)
		}
	}
	c.checkMember("cihaz", filepath.Join(dir, DeviceDir), deviceKeyFile)
	if exists(filepath.Join(dir, CoordinatorDir, "anchor.json")) {
		c.checkMember("koordinatör", filepath.Join(dir, CoordinatorDir), coordKeyFile)
		if st.CoordinatorPort == 0 {
			c.add(FindingError, "koordinatör", "koordinatör portu ayarlanmamış")
		}
	}
	if PanelReadOnly(dir) {
		c.add(FindingInfo, "panel", "panel salt okunur (openscale panel readonly off ile açılır)")
	}
	if serviceRunning {
		c.add(FindingOK, "servis", "servis çalışıyor ve yanıt veriyor; portları servis kullanıyor")
	} else {
		c.add(FindingInfo, "servis", "servis yanıt vermiyor; portlar denetleniyor")
		c.probePorts(st, panelPort)
	}
	return c.out
}

// CheckStateDir checks the state directory of a foreground "openscale up"
// or "coordinator run".
func CheckStateDir(dir string, now time.Time) []Finding {
	c := &checker{now: now}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		c.add(FindingInfo, "durum klasörü", "durum klasörü yok: %s", dir)
		return c.out
	}
	switch {
	case exists(filepath.Join(dir, coordKeyFile)):
		c.checkMember("koordinatör", dir, coordKeyFile)
	default:
		c.checkMember("cihaz", dir, deviceKeyFile)
	}
	return c.out
}
