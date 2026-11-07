package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/version"
)

// Start-up self-check (#172, ADR-0095). When the service starts it
// repairs damaged member state from the local copies (#206), keeps a disk
// reserve for the document (#205) and then, without delaying the start,
// checks what can silently go wrong: the program against the signed
// manifest of the last update, the data directory's permissions, the
// clock, the documents and memberships (CheckDataDir), free disk space and
// an interrupted update. Findings go to the log and the event list and are
// saved as update/selfcheck.json, which "openscale selfcheck --last"
// shows. Once the service is ready it writes update/running.json, which
// the updater waits for (#204).

const (
	// UpdateDir holds the update journal, the marker and the self-check.
	UpdateDir     = "update"
	selfCheckFile = "selfcheck.json"
	maxSelfCheck  = 256 << 10
	// buildClockSlack: a clock this far before the build time is wrong.
	buildClockSlack = 24 * time.Hour
)

// SelfCheckReport is the saved result of the start-up self-check.
type SelfCheckReport struct {
	At       time.Time `json:"at"`
	Version  string    `json:"version"`
	Findings []Finding `json:"findings"`
}

// RepairMemberStores opens the device and coordinator state directories,
// which repairs damaged files from the local copies, and returns what was
// repaired or what still needs the owner.
func RepairMemberStores(dataDir string) []Finding {
	c := &checker{}
	for _, d := range []struct{ area, dir string }{{"cihaz", DeviceDir}, {"koordinatör", CoordinatorDir}} {
		dir := filepath.Join(dataDir, d.dir)
		if !exists(filepath.Join(dir, "anchor.json")) {
			continue
		}
		store, err := member.Open(dir)
		switch {
		case errors.Is(err, member.ErrNeedsDocument):
			c.add(FindingError, d.area, "ağ belgesinin bütün yerel kopyaları bozuk; başka bir cihazın network.json dosyasıyla: openscale state repair --state-dir %s --document <dosya>", dir)
		case err != nil:
			// CheckDataDir reports other errors.
		default:
			for _, note := range store.Recovered() {
				c.add(FindingWarn, d.area, "kurtarma: %s", note)
			}
		}
	}
	return c.out
}

// SelfCheck runs every start-up check on a data directory. exe is the
// running program; empty skips the integrity check.
func SelfCheck(dataDir string, now time.Time, exe string, serviceRunning bool, panelPort int) []Finding {
	c := &checker{now: now}
	c.checkDataDirPermissions(dataDir)
	c.checkProgram(filepath.Join(dataDir, UpdateDir), exe)
	c.checkBuildClock()
	c.checkDiskSpace(dataDir)
	c.checkPendingUpdate(filepath.Join(dataDir, UpdateDir))
	c.out = append(c.out, CheckDataDir(dataDir, now, serviceRunning, panelPort)...)
	return c.out
}

// SelfCheckExtras runs the checks that are not about a service data
// directory, for a foreground or Linux state directory: the program, the
// clock, free space and an interrupted update.
func SelfCheckExtras(updateDir, stateDir string, now time.Time, exe string) []Finding {
	c := &checker{now: now}
	c.checkDataDirPermissions(stateDir)
	c.checkProgram(updateDir, exe)
	c.checkBuildClock()
	c.checkDiskSpace(stateDir)
	c.checkPendingUpdate(updateDir)
	return c.out
}

func (c *checker) checkDataDirPermissions(dir string) {
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	if runtime.GOOS == "windows" {
		// The ACL is set when the service is installed (ADR-0014) and
		// key files are read only by SYSTEM and administrators.
		c.checkWindowsDataDir(dir)
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		c.add(FindingError, "veri klasörü", "%s başka kullanıcılara açık (%o); chmod 700 %s", dir, info.Mode().Perm(), dir)
		return
	}
	c.add(FindingOK, "veri klasörü", "veri klasörü yalnızca servis hesabına açık")
}

func (c *checker) checkProgram(updateDir, exe string) {
	if exe == "" {
		return
	}
	root, _, err := updater.LoadRootKey("")
	if err != nil {
		c.add(FindingInfo, "program", "sürüm kök açık anahtarı yok; program bütünlüğü denetlenmedi")
		return
	}
	v, ok, err := updater.CheckInstalled(updateDir, exe, root, c.now)
	switch {
	case errors.Is(err, release.ErrRevoked):
		// The start-up check refuses this program; report it at the same level.
		c.add(FindingError, "program", "kurulu sürümün imzalama anahtarı iptal edilmiş: %v; programı imzalı yeni bir sürümden kurun", err)
	case err != nil && v != "":
		c.add(FindingError, "program", "program dosyası imzalı %s sürümüyle eşleşmiyor: %v; programı imzalı sürümden yeniden kurun", v, err)
	case err != nil:
		c.add(FindingWarn, "program", "kurulu sürümün imzalı manifestosu doğrulanamadı: %v", err)
	case !ok:
		c.add(FindingInfo, "program", "kurulu sürümün imzalı manifestosu yok (elle veya paketle kurulmuş); bütünlük denetimi atlandı")
	default:
		c.add(FindingOK, "program", "program imzalı %s sürümüyle bayt bayt aynı", v)
	}
}

// checkBuildClock: a clock earlier than this program's build is wrong
// (#192); documents would look "not yet valid" and handshakes may fail.
func (c *checker) checkBuildClock() {
	if version.Build == "" {
		return
	}
	built, err := time.Parse("20060102.1504", version.Build)
	if err != nil {
		return
	}
	if c.now.Before(built.Add(-buildClockSlack)) {
		c.add(FindingWarn, "saat", "bu bilgisayarın saati programın derlenme zamanından (%s) önce görünüyor; saati düzeltin", built.Format("02.01.2006 15:04"))
	}
}

func (c *checker) checkDiskSpace(dir string) {
	free, err := diskguard.Free(dir)
	if err != nil {
		return
	}
	if free < diskguard.DefaultLowWater {
		c.add(FindingWarn, "disk", "veri klasörünün diskinde yalnızca %d MB boş; günlükler duraklatıldı, belge yazımı yedek alanı kullanır", free>>20)
		return
	}
	c.add(FindingOK, "disk", "diskte yeterli boş alan var (%d MB)", free>>20)
}

func (c *checker) checkPendingUpdate(updateDir string) {
	j, err := updater.ReadJournal(updateDir)
	if err != nil {
		c.add(FindingWarn, "güncelleme", "%v", err)
		return
	}
	if j != nil {
		c.add(FindingWarn, "güncelleme", "%s -> %s güncellemesi yarım kalmış (%s); 'openscale update status' ve gerekirse 'openscale update rollback'", j.From, j.To, j.State)
	}
}

// LastSelfCheck reads the saved start-up self-check.
func LastSelfCheck(dataDir string) (*SelfCheckReport, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dataDir, UpdateDir, selfCheckFile), maxSelfCheck)
	if err != nil {
		return nil, err
	}
	var r SelfCheckReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("selfcheck.json bozuk: %w", err)
	}
	return &r, nil
}

func saveSelfCheck(dataDir string, r SelfCheckReport) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir, UpdateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, selfCheckFile), data)
}

// startupSelfCheck is called by Run before any role starts.
func (r *Runtime) startupSelfCheck(ctx context.Context) {
	for _, f := range RepairMemberStores(r.cfg.DataDir) {
		r.logger.Warn("self-check", "area", f.Area, "message", f.Message)
	}
	for _, d := range []string{r.cfg.DataDir, r.path(DeviceDir), r.path(CoordinatorDir), r.path(NetworkDir)} {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			if err := diskguard.EnsureReserve(d, 0); err != nil {
				r.logger.Warn("disk reserve", "dir", d, "error", err.Error())
			}
		}
	}
	exe, _ := os.Executable()
	r.spawn(func() {
		now := r.cfg.Now()
		findings := SelfCheck(r.cfg.DataDir, now, exe, true, r.cfg.PanelPort)
		problems := 0
		for _, f := range findings {
			switch f.Level {
			case FindingError:
				problems++
				r.logger.Error("self-check", "area", f.Area, "message", f.Message)
			case FindingWarn:
				problems++
				r.logger.Warn("self-check", "area", f.Area, "message", f.Message)
			default:
				continue
			}
			r.eventLog().Add(panel.DiagEvent{At: now, Kind: "selfcheck", Message: f.Area + ": " + f.Message})
		}
		r.logger.Info("self-check done", "problems", problems)
		if err := saveSelfCheck(r.cfg.DataDir, SelfCheckReport{At: now.UTC(), Version: version.Version, Findings: findings}); err != nil {
			r.logger.Warn("self-check report", "error", err.Error())
		}
	})
	r.spawn(func() {
		select {
		case <-r.ready:
		case <-ctx.Done():
			return
		}
		m := updater.Marker{Version: version.Version, PID: os.Getpid(), Started: r.cfg.Now().UTC()}
		if err := updater.WriteMarkerFile(r.path(UpdateDir), m); err != nil {
			r.logger.Warn("start marker", "error", err.Error())
		}
	})
}
