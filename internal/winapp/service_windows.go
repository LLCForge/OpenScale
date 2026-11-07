//go:build windows

package winapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	installedExeName = "openscale.exe"
	stateWaitTimeout = 15 * time.Second
	runStopTimeout   = 20 * time.Second
	statePollEvery   = 250 * time.Millisecond

	// SYSTEM and Administrators get full control, owner is Administrators,
	// the DACL is protected so nothing is inherited from %ProgramData%.
	dataDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

// InstallDir returns %ProgramFiles%\OpenScale.
func InstallDir() string {
	return filepath.Join(knownFolder(windows.FOLDERID_ProgramFiles, "ProgramFiles", `C:\Program Files`), "OpenScale")
}

// DataDir returns %ProgramData%\OpenScale.
func DataDir() string {
	return filepath.Join(knownFolder(windows.FOLDERID_ProgramData, "ProgramData", `C:\ProgramData`), "OpenScale")
}

func knownFolder(id *windows.KNOWNFOLDERID, env, fallback string) string {
	if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
		return p
	}
	if p := os.Getenv(env); p != "" && filepath.IsAbs(p) {
		return p
	}
	return fallback
}

func serviceBinaryPath(exePath string) string {
	return `"` + exePath + `" service run`
}

// InstallService copies srcExe to InstallDir()\openscale.exe (unless it is
// already that file or byte-identical), prepares DataDir() with a locked-down
// ACL and creates or updates the OpenScale service. If the binary had to be
// replaced while the service was running, the service is stopped first; the
// caller is expected to call StartService afterwards.
func InstallService(srcExe string) (string, error) {
	src, err := filepath.Abs(srcExe)
	if err != nil {
		return "", fmt.Errorf("kaynak program yolu geçersiz: %w", err)
	}
	dir := InstallDir()
	dst := filepath.Join(dir, installedExeName)
	if _, err := validateProgramPath(dst); err != nil {
		return "", fmt.Errorf("kurulum yolu kullanılamıyor: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", wrapWinErr("kurulum klasörü oluşturulamadı", err)
	}
	removeStaleBinaries(dir)

	if err := installBinary(src, dst); err != nil {
		return "", err
	}
	// The service runs as SYSTEM: refuse a program or folder a standard
	// user could change (F-124), e.g. a pre-created OpenScale folder with
	// a weak ACL.
	if err := CheckTrustedPath(dst); err != nil {
		return "", fmt.Errorf("kurulu program güvenli bir konumda değil: %w", err)
	}
	if err := prepareDataDir(DataDir()); err != nil {
		return "", err
	}
	if err := ensureService(dst); err != nil {
		return "", err
	}
	// Start the tray at every user's sign-in (ADR-0194). Best effort: the
	// service runs at boot either way, and the user's own setting decides
	// whether "autostart run" shows anything.
	if cmd, err := RunCommand(dst, "autostart", "run"); err == nil {
		_ = SetRunEntry(true, cmd)
	}
	// Best effort as well: the program works without shortcuts, and without
	// the task the Run entry still starts the tray (with a consent prompt).
	_ = installShortcuts(dst)
	_ = installTrayTask(dst)
	return dst, nil
}

// installBinary copies the running program to dst.
//
// SECURITY FIX: CWE-367 The source path is writable by lower-trust
// processes and is re-read after the UAC consent. One locked handle, shown
// to be this process's own image, is used for everything, so what becomes
// the LocalSystem service is what was consented to (installsource_windows.go).
func installBinary(src, dst string) error {
	in, err := openLockedSource(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := checkIsRunningImage(in); err != nil {
		return err
	}
	srcInfo, err := in.Stat()
	if err != nil {
		return fmt.Errorf("kaynak program okunamadı: %w", err)
	}
	if !srcInfo.Mode().IsRegular() {
		return errors.New("kaynak program normal bir dosya değil")
	}
	if dstInfo, err := os.Stat(dst); err == nil {
		if os.SameFile(srcInfo, dstInfo) || strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
			return nil // running the installed copy: never copy onto itself
		}
		srcSum, err := hashHandle(in)
		if err != nil {
			return err
		}
		dstSum, err := fileSHA256(dst)
		if err != nil {
			return err
		}
		if srcSum == dstSum {
			return nil
		}
		// The running service keeps the old image mapped; stop it so the new
		// binary is what starts next.
		if running, err := ServiceRunning(); err == nil && running {
			if err := StopService(); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("kurulu program okunamadı: %w", err)
	}
	return atomicCopy(in, dst)
}

func fileSHA256(p string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(p)
	if err != nil {
		return sum, fmt.Errorf("dosya okunamadı: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("dosya okunamadı: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// atomicCopy writes in, from its start, to a temporary file next to dst and
// renames it into place once the copy's hash matches the source's. If dst is
// in use (an executable image cannot be overwritten but can be renamed), the
// old file is moved aside first and deleted later.
func atomicCopy(in *os.File, dst string) (err error) {
	dir := filepath.Dir(dst)
	want, err := hashHandle(in)
	if err != nil {
		return err
	}
	if _, err = in.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("kaynak program okunamadı: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".openscale-*.tmp")
	if err != nil {
		return wrapWinErr("geçici dosya oluşturulamadı", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("program kopyalanamadı: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("program diske yazılamadı: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("program diske yazılamadı: %w", err)
	}
	got, err := fileSHA256(tmpName)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("kopyalanan program kaynakla aynı değil; kurulum durduruldu")
	}

	if err = os.Rename(tmpName, dst); err == nil {
		return nil
	}
	// dst is probably a running image: move it aside, then retry.
	aside := dst + ".old-" + randomSuffix()
	if mvErr := os.Rename(dst, aside); mvErr != nil {
		return wrapWinErr("kurulu program değiştirilemedi", err)
	}
	if err = os.Rename(tmpName, dst); err != nil {
		_ = os.Rename(aside, dst) // best-effort rollback
		return wrapWinErr("kurulu program değiştirilemedi", err)
	}
	if rmErr := os.Remove(aside); rmErr != nil {
		if p, convErr := windows.UTF16PtrFromString(aside); convErr == nil {
			_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
	}
	return nil
}

func removeStaleBinaries(dir string) {
	matches, err := filepath.Glob(filepath.Join(dir, installedExeName+".old-*"))
	if err != nil {
		return
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
	tmps, err := filepath.Glob(filepath.Join(dir, ".openscale-*.tmp"))
	if err != nil {
		return
	}
	for _, m := range tmps {
		_ = os.Remove(m)
	}
}

func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// prepareDataDir creates dir and restricts it to SYSTEM and Administrators.
// %ProgramData% lets ordinary users create sub-folders, so a pre-existing
// directory must be owned by SYSTEM or Administrators and must not be a
// reparse point (junction/symlink) before we trust it.
//
// SECURITY FIX: CWE-362 A new folder has its protected ACL from the moment
// it exists, so nobody can slip a sub-folder of their own into it; what an
// older install left behind is checked once the ACL is locked
// (datadir_windows.go).
func prepareDataDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return wrapWinErr("veri klasörü oluşturulamadı", err)
	}
	if _, err := createProtectedDir(dir, dataDirSDDL); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("veri klasörü yolu geçersiz: %w", err)
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return wrapWinErr("veri klasörü okunamadı", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("veri klasörü güvenli değil (bağlantı noktası veya dosya): %s", dir)
	}
	cur, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return wrapWinErr("veri klasörünün sahibi okunamadı", err)
	}
	owner, _, err := cur.Owner()
	if err != nil || owner == nil {
		return errors.New("veri klasörünün sahibi okunamadı")
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("veri klasörü başka bir kullanıcıya ait; güvenlik için silip yeniden deneyin: %s", dir)
	}

	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return fmt.Errorf("güvenlik tanımı oluşturulamadı: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("güvenlik tanımı oluşturulamadı: %w", err)
	}
	newOwner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("güvenlik tanımı oluşturulamadı: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION | windows.OWNER_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, newOwner, nil, dacl, nil); err != nil {
		return wrapWinErr("veri klasörünün izinleri ayarlanamadı", err)
	}
	return auditDataTree(dir, trustedDataOwner)
}

func ensureService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return wrapWinErr("servis yöneticisine bağlanılamadı", err)
	}
	defer m.Disconnect()

	want := serviceBinaryPath(exePath)
	display, desc := CurrentDiscreet().ServiceIdentity() // #687, ADR-0196
	s, err := m.OpenService(ServiceName)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		s, err = m.CreateService(ServiceName, exePath, mgr.Config{
			ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:        serviceStartType,
			ErrorControl:     mgr.ErrorNormal,
			ServiceStartName: "LocalSystem",
			DisplayName:      display,
			Description:      desc,
		}, "service", "run")
		if err != nil {
			return wrapWinErr("servis oluşturulamadı", err)
		}
	case err != nil:
		return wrapWinErr("servis açılamadı", err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return wrapWinErr("servis ayarları okunamadı", err)
	}
	if cfg.BinaryPathName != want || cfg.StartType != serviceStartType ||
		cfg.DisplayName != display || cfg.Description != desc ||
		cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
		cfg.BinaryPathName = want
		cfg.StartType = serviceStartType
		cfg.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
		cfg.DisplayName = display
		cfg.Description = desc
		cfg.Password = ""
		if err := s.UpdateConfig(cfg); err != nil {
			return wrapWinErr("servis ayarları güncellenemedi", err)
		}
	}

	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		return wrapWinErr("servis kurtarma ayarları yapılamadı", err)
	}
	// Treat a non-zero exit code (run returned an error) like a crash.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return wrapWinErr("servis kurtarma ayarları yapılamadı", err)
	}
	return nil
}

// StartService starts the service and waits (up to 15s) until it runs.
func StartService() error {
	m, s, err := openService()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return wrapWinErr("servis başlatılamadı", err)
	}
	st, err := waitState(s, svc.Running, svc.StartPending)
	if err != nil {
		return err
	}
	if st != svc.Running {
		return errors.New("servis başlatılamadı; ayrıntılar için Olay Görüntüleyicisi'ne bakın")
	}
	return nil
}

// StopService stops the service and waits (up to 15s) until it has stopped.
// A service that is not running is not an error.
func StopService() error {
	m, s, err := openService()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return stopAndWait(s)
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return wrapWinErr("servis durumu okunamadı", err)
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return wrapWinErr("servis durdurulamadı", err)
		}
	}
	if _, err := waitState(s, svc.Stopped, svc.StopPending, svc.Running); err != nil {
		return err
	}
	return nil
}

// waitState polls until the service leaves the transitional states or the
// target is reached, for at most stateWaitTimeout.
func waitState(s *mgr.Service, target svc.State, transitional ...svc.State) (svc.State, error) {
	deadline := time.Now().Add(stateWaitTimeout)
	for {
		st, err := s.Query()
		if err != nil {
			return 0, wrapWinErr("servis durumu okunamadı", err)
		}
		if st.State == target {
			return st.State, nil
		}
		waiting := false
		for _, t := range transitional {
			if st.State == t {
				waiting = true
				break
			}
		}
		if !waiting {
			return st.State, nil
		}
		if time.Now().After(deadline) {
			return st.State, errors.New("servis 15 saniye içinde yanıt vermedi")
		}
		time.Sleep(statePollEvery)
	}
}

// ServiceRunning reports whether the service is installed and running. It
// needs only query rights, so it also works from a non-elevated tray.
func ServiceRunning() (bool, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, wrapWinErr("servis yöneticisine bağlanılamadı", err)
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return false, err
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, wrapWinErr("servis açılamadı", err)
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return false, wrapWinErr("servis durumu okunamadı", err)
	}
	return st.CurrentState == windows.SERVICE_RUNNING, nil
}

// UninstallService stops and deletes the service. A missing service is not
// an error. Installed files and DataDir() are left in place.
func UninstallService() error {
	// The sign-in entries go with the service (ADR-0194).
	_ = DeleteRunEntry(true)
	_ = DeleteRunEntry(false)
	removeShortcuts()
	removeTrayTask()
	m, s, err := openService()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if err := stopAndWait(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return wrapWinErr("servis kaldırılamadı", err)
	}
	return nil
}

func openService() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, wrapWinErr("servis yöneticisine bağlanılamadı", err)
	}
	s, err := m.OpenService(ServiceName)
	if err != nil {
		_ = m.Disconnect()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, nil, fmt.Errorf("OpenScale servisi kurulu değil: %w", err)
		}
		return nil, nil, wrapWinErr("servis açılamadı", err)
	}
	return m, s, nil
}

// RunService runs run under the Service Control Manager when the process was
// started as a service, otherwise directly with a context cancelled on
// Ctrl+C. The run error is returned (and reported to the SCM as a
// service-specific exit code so recovery actions apply).
func RunService(run func(ctx context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("servis ortamı algılanamadı: %w", err)
	}
	if !isService {
		return runConsole(run)
	}
	// #494: a memory ceiling (job object) before any work starts. A bad
	// override falls back to the defaults and is reported, never fatal.
	lim, limErr := ParseResourceLimits(os.Getenv)
	if limErr != nil {
		lim, _ = ParseResourceLimits(func(string) string { return "" })
		lim = LimitServiceResources(lim)
		lim.Error = limErr.Error()
		recordLimits(lim)
	} else {
		LimitServiceResources(lim)
	}
	h := &serviceHandler{run: run}
	if err := svc.Run(ServiceName, h); err != nil {
		return fmt.Errorf("servis çalıştırılamadı: %w", err)
	}
	return h.err
}

type serviceHandler struct {
	run func(ctx context.Context) error
	err error // written by Execute before svc.Run returns
}

const (
	exitRunFailed   = 1
	exitStopTimeout = 2
)

func (h *serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending, WaitHint: 10000}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	done := make(chan error, 1)
	go func() { done <- safeRun(ctx, h.run) }()

	status <- svc.Status{State: svc.Running, Accepts: accepts}

	for {
		select {
		case err := <-done:
			return h.finish(err)
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				checkpoint := uint32(1)
				status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: uint32(runStopTimeout / time.Millisecond)}
				// The run function tells a shutdown from a requested stop
				// through the cause (the kill switch survives a shutdown).
				var cause error
				if c.Cmd == svc.Shutdown {
					cause = ErrSystemShutdown
				}
				cancel(cause)
				timeout := time.NewTimer(runStopTimeout)
				tick := time.NewTicker(2 * time.Second)
				for {
					select {
					case err := <-done:
						timeout.Stop()
						tick.Stop()
						// A requested stop is never reported as a failure, so
						// recovery actions do not restart a service the user stopped.
						if err != nil && !errors.Is(err, context.Canceled) {
							h.err = err
						}
						return false, 0
					case <-tick.C:
						checkpoint++
						status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: uint32(runStopTimeout / time.Millisecond)}
					case <-timeout.C:
						tick.Stop()
						h.err = errors.New("servis 20 saniye içinde durmadı")
						return true, exitStopTimeout
					}
				}
			}
		}
	}
}

func (h *serviceHandler) finish(err error) (bool, uint32) {
	if err != nil && !errors.Is(err, context.Canceled) {
		h.err = err
		return true, exitRunFailed
	}
	return false, 0
}

// safeRun converts a panic in run into an error so the SCM sees a failure
// exit code instead of the process vanishing mid-report.
func safeRun(ctx context.Context, run func(ctx context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("servis beklenmedik şekilde çöktü: %v\n%s", r, debug.Stack())
		}
	}()
	return run(ctx)
}

// wrapWinErr adds a Turkish context and a clearer hint for access denied.
func wrapWinErr(op string, err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s: yönetici izni gerekiyor: %w", op, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}
