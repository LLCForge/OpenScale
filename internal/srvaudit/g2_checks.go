package srvaudit

import (
	"encoding/json"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// G2 server checks (ADR-0184): LUKS with remote unlock through the tunnel
// (#634), core dumps (#638) and the no-metadata mode (#630). Like the rest
// of the audit they only read files.

// CoordinatorStateDir is the coordinator's state directory under the
// shipped unit (relative to the audited root).
const CoordinatorStateDir = "var/lib/openscale/coordinator"

// g2Checks are added to Run for every role; checks that do not apply
// answer Unknown and are left out of the score.
func g2Checks(fsys fs.FS, o Options) []Check {
	checks := []Check{checkLUKSRemoteUnlock(fsys), checkCoreDumps(fsys, o.Role)}
	if o.Role == RoleCoordinator {
		checks = append(checks, checkNoMetadata(fsys))
	}
	return checks
}

// --- #634: LUKS root and dropbear-initramfs unlock through the tunnel ---

// rootOnLUKS follows the root file system's device through device mapper
// (LVM inside LUKS included) and reports whether a LUKS mapping is below it.
// ok is false when /proc/mounts or /sys cannot be read.
func rootOnLUKS(fsys fs.FS) (luks, ok bool) {
	mounts, err := readSmall(fsys, "proc/mounts")
	if err != nil {
		return false, false
	}
	var dev string
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "/" {
			dev = f[0] // the last mount of / wins
		}
	}
	if dev == "" {
		return false, false
	}
	dm := ""
	switch {
	case strings.HasPrefix(dev, "/dev/dm-"):
		dm = strings.TrimPrefix(dev, "/dev/")
	case strings.HasPrefix(dev, "/dev/mapper/"):
		dm = dmByName(fsys, strings.TrimPrefix(dev, "/dev/mapper/"))
	default:
		return false, true
	}
	if dm == "" {
		return false, true
	}
	return dmIsLUKS(fsys, dm, 0), true
}

func dmByName(fsys fs.FS, name string) string {
	entries, err := fs.ReadDir(fsys, "sys/block")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dm-") {
			continue
		}
		if n, err := readSmall(fsys, "sys/block/"+e.Name()+"/dm/name"); err == nil && strings.TrimSpace(n) == name {
			return e.Name()
		}
	}
	return ""
}

func dmIsLUKS(fsys fs.FS, dm string, depth int) bool {
	if depth > 4 {
		return false
	}
	if uuid, err := readSmall(fsys, "sys/block/"+dm+"/dm/uuid"); err == nil && strings.HasPrefix(strings.TrimSpace(uuid), "CRYPT-LUKS") {
		return true
	}
	slaves, err := fs.ReadDir(fsys, "sys/block/"+dm+"/slaves")
	if err != nil {
		return false
	}
	for _, s := range slaves {
		if strings.HasPrefix(s.Name(), "dm-") && dmIsLUKS(fsys, s.Name(), depth+1) {
			return true
		}
	}
	return false
}

// dropbearConfig returns the initramfs dropbear options and authorized keys
// (Debian 12+ layout first, then the older one).
func dropbearConfig(fsys fs.FS) (options, keys string, found bool) {
	for _, layout := range [][2]string{
		{"etc/dropbear/initramfs/dropbear.conf", "etc/dropbear/initramfs/authorized_keys"},
		{"etc/dropbear-initramfs/config", "etc/dropbear-initramfs/authorized_keys"},
	} {
		conf, err := readSmall(fsys, layout[0])
		if err != nil {
			continue
		}
		k, _ := readSmall(fsys, layout[1])
		for _, line := range strings.Split(conf, "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "DROPBEAR_OPTIONS="); ok {
				options = strings.Trim(v, `"'`)
			}
		}
		return options, k, true
	}
	return "", "", false
}

// dropbearListen returns the -p values of the options.
func dropbearListen(options string) []string {
	f := strings.Fields(options)
	var out []string
	for i := 0; i < len(f); i++ {
		switch {
		case f[i] == "-p" && i+1 < len(f):
			out = append(out, f[i+1])
			i++
		case strings.HasPrefix(f[i], "-p") && len(f[i]) > 2:
			out = append(out, f[i][2:])
		}
	}
	return out
}

// hasFlag reports whether a one-letter flag (e.g. "-s") is set, alone or
// in a group such as "-sjk". Values of -p and -c are skipped.
func hasFlag(options, flag string) bool {
	f := strings.Fields(options)
	for i := 0; i < len(f); i++ {
		w := f[i]
		if w == "-p" || w == "-c" || w == "-r" {
			i++ // option value
			continue
		}
		if len(w) < 2 || w[0] != '-' || w[1] == '-' {
			continue
		}
		letters := w[1:]
		if strings.IndexFunc(letters, func(r rune) bool { return r < 'a' || r > 'z' }) >= 0 {
			continue
		}
		if strings.ContainsRune(letters, rune(flag[1])) {
			return true
		}
	}
	return false
}

// tunnelInInitramfs reports whether a WireGuard hook ships in the initramfs.
func tunnelInInitramfs(fsys fs.FS) bool {
	if exists(fsys, "etc/wireguard-initramfs/config") || exists(fsys, "etc/wireguard-initramfs") {
		return true
	}
	for _, d := range []string{"etc/initramfs-tools/hooks", "usr/share/initramfs-tools/hooks"} {
		entries, err := fs.ReadDir(fsys, d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Name()), "wireguard") {
				return true
			}
		}
	}
	return false
}

func checkLUKSRemoteUnlock(fsys fs.FS) Check {
	c := Check{ID: "luks-unlock", Title: "Şifreli disk ve tünelden kilit açma", Weight: 10}
	luks, ok := rootOnLUKS(fsys)
	if !ok {
		c.Status, c.Detail = Unknown, "/proc/mounts veya /sys okunamadı."
		return c
	}
	if !luks {
		c.Status, c.Detail = Fail, "Kök dosya sistemi LUKS üzerinde değil; sağlayıcı diski kopyalarsa anahtarlar okunur."
		c.Fix = "Rehber: deploy/linux/luks-dropbear-rehberi.md (yeni kurulumda LUKS, açılışta dropbear-initramfs ile tünelden kilit açma)."
		return c
	}
	opts, keys, found := dropbearConfig(fsys)
	if !found {
		c.Status, c.Detail = Warn, "Kök disk LUKS ile şifreli; uzaktan kilit açma (dropbear-initramfs) kurulu değil, her açılışta seri konsol gerekir."
		c.Fix = "apt install dropbear-initramfs; ayarlar için deploy/linux/luks-dropbear-rehberi.md"
		return c
	}
	var problems []string
	if strings.TrimSpace(keys) == "" {
		problems = append(problems, "authorized_keys boş")
	}
	if !hasFlag(opts, "-s") {
		problems = append(problems, "parola girişi kapalı değil (-s yok)")
	}
	if !hasFlag(opts, "-j") || !hasFlag(opts, "-k") {
		problems = append(problems, "port yönlendirme kapalı değil (-j -k yok)")
	}
	listen := dropbearListen(opts)
	public := len(listen) == 0
	for _, l := range listen {
		if !strings.Contains(l, ":") || strings.HasPrefix(l, "0.0.0.0:") || strings.HasPrefix(l, "[::]:") {
			public = true
		}
	}
	tunnel := tunnelInInitramfs(fsys)
	if public && !tunnel {
		problems = append(problems, "dropbear bütün adreslerde dinliyor ve initramfs'te WireGuard yok")
	}
	if len(problems) > 0 {
		c.Status, c.Detail = Warn, "dropbear-initramfs kurulu ama: "+strings.Join(problems, "; ")+"."
		c.Fix = "DROPBEAR_OPTIONS=\"-s -j -k -p <tünel-ip>:2222 -c cryptroot-unlock\"; ayrıntı: deploy/linux/luks-dropbear-rehberi.md"
		return c
	}
	c.Status, c.Detail = Pass, "Kök disk LUKS ile şifreli; kilit yalnızca anahtarla, yönlendirmesiz dropbear üzerinden açılıyor."
	if tunnel {
		c.Detail += " Açılışta WireGuard tüneli kuruluyor."
	}
	return c
}

// --- #638: core dumps ---

func checkCoreDumps(fsys fs.FS, role string) Check {
	c := Check{ID: "core-dumps", Title: "Bellek dökümü", Weight: 5}
	unit := "openscale-coordinator.service"
	if role == RoleExit {
		unit = "openscale-device.service"
	}
	vals, _, found := unitSettings(fsys, unit)
	limitOK := found && strings.EqualFold(strings.TrimSpace(vals["LimitCORE"]), "0")
	storageNone := coredumpStorage(fsys) == "none"
	pattern, _ := readSmall(fsys, "proc/sys/kernel/core_pattern")
	pattern = strings.TrimSpace(pattern)
	switch {
	case limitOK && (storageNone || !strings.HasPrefix(pattern, "|")):
		c.Status, c.Detail = Pass, "Servis biriminde LimitCORE=0; program ayrıca PR_SET_DUMPABLE=0 yapar."
	case storageNone:
		c.Status, c.Detail = Pass, "systemd-coredump hiçbir dökümü saklamıyor (Storage=none); program ayrıca PR_SET_DUMPABLE=0 yapar."
	case !found:
		c.Status, c.Detail = Unknown, unit+" bulunamadı."
	default:
		c.Status = Warn
		c.Detail = "Program kendi dökümünü kapatıyor (PR_SET_DUMPABLE=0, RLIMIT_CORE=0) ama birimde LimitCORE=0 yok"
		if strings.HasPrefix(pattern, "|") {
			c.Detail += " ve çekirdek dökümleri bir programa aktarılıyor (" + pattern + ")"
		}
		c.Detail += "."
		c.Fix = "Birime LimitCORE=0 ekleyin (deploy/linux birimleri bunu içerir) ve /etc/systemd/coredump.conf.d/ içinde Storage=none ayarlayın."
	}
	return c
}

func coredumpStorage(fsys fs.FS) string {
	v := ""
	read := func(p string) {
		data, err := readSmall(fsys, p)
		if err != nil {
			return
		}
		for _, line := range strings.Split(data, "\n") {
			if s, ok := strings.CutPrefix(strings.TrimSpace(line), "Storage="); ok {
				v = strings.ToLower(strings.TrimSpace(s))
			}
		}
	}
	read("etc/systemd/coredump.conf")
	for _, d := range []string{"usr/lib/systemd/coredump.conf.d", "etc/systemd/coredump.conf.d"} {
		entries, _ := fs.ReadDir(fsys, d)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		slices.Sort(names)
		for _, n := range names {
			if strings.HasSuffix(n, ".conf") {
				read(path.Join(d, n))
			}
		}
	}
	return v
}

// --- #630: no metadata on disk ---

func journalStorage(fsys fs.FS) string {
	v := ""
	read := func(p string) {
		data, err := readSmall(fsys, p)
		if err != nil {
			return
		}
		for _, line := range strings.Split(data, "\n") {
			if s, ok := strings.CutPrefix(strings.TrimSpace(line), "Storage="); ok {
				v = strings.ToLower(strings.TrimSpace(s))
			}
		}
	}
	read("etc/systemd/journald.conf")
	for _, d := range []string{"usr/lib/systemd/journald.conf.d", "etc/systemd/journald.conf.d"} {
		entries, _ := fs.ReadDir(fsys, d)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				read(path.Join(d, e.Name()))
			}
		}
	}
	if v == "" {
		v = "auto"
	}
	return v
}

// hardeningNoMetadata reads the coordinator's hardening file.
func hardeningNoMetadata(fsys fs.FS) (on, ok bool) {
	data, err := readSmall(fsys, CoordinatorStateDir+"/coordinator-hardening.json")
	if err != nil {
		return false, false
	}
	var h struct {
		NoMetadata bool `json:"no_metadata"`
	}
	if json.Unmarshal([]byte(data), &h) != nil {
		return false, false
	}
	return h.NoMetadata, true
}

func checkNoMetadata(fsys fs.FS) Check {
	c := Check{ID: "no-metadata", Title: "Bağlantı meta verisi diskte", Weight: 5}
	on, ok := hardeningNoMetadata(fsys)
	if !ok {
		c.Status, c.Detail = Unknown, "Koordinatör sertleştirme dosyası okunamadı (root olarak çalıştırın) veya yok."
		return c
	}
	if !on {
		c.Status, c.Detail = Warn, "Kayıt tutmama kipi kapalı: aktarıcı kullanımı diske yazılır, ayrıntılı günlük uç noktaları içerebilir."
		c.Fix = "openscale coordinator harden --no-metadata on --state-dir /var/lib/openscale/coordinator"
		return c
	}
	var problems []string
	if exists(fsys, CoordinatorStateDir+"/relay-usage.json") {
		problems = append(problems, "eski relay-usage.json hâlâ duruyor")
	}
	switch st := journalStorage(fsys); st {
	case "volatile", "none":
	case "auto":
		if exists(fsys, "var/log/journal") {
			problems = append(problems, "journald günlükleri diske yazıyor (/var/log/journal var)")
		}
	default:
		problems = append(problems, "journald Storage="+st)
	}
	if len(problems) > 0 {
		c.Status, c.Detail = Fail, "Kayıt tutmama kipi açık ama: "+strings.Join(problems, "; ")+"."
		c.Fix = "relay-usage.json dosyasını silin; /etc/systemd/journald.conf.d/50-openscale.conf: [Journal] Storage=volatile"
		return c
	}
	c.Status, c.Detail = Pass, "Kayıt tutmama kipi açık; kullanım dosyası yok, journald diske yazmıyor."
	return c
}
