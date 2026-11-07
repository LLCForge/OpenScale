//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// IsElevated reports whether the current process runs with an elevated
// (administrator) token.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchElevated starts the current executable again through the UAC
// prompt ("runas") with args, using the executable's directory as working
// directory. It returns once the new process has been started; the caller
// normally exits afterwards.
func RelaunchElevated(args []string) error {
	exe, err := currentExecutable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return fmt.Errorf("program yolu geçersiz: %w", err)
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return fmt.Errorf("program klasörü geçersiz: %w", err)
	}
	var argp *uint16
	if line := joinArgs(args); line != "" {
		if argp, err = windows.UTF16PtrFromString(line); err != nil {
			return fmt.Errorf("komut satırı geçersiz: %w", err)
		}
	}
	if err := windows.ShellExecute(0, verb, file, argp, dir, windows.SW_SHOWNORMAL); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errors.New("Yönetici izni verilmedi.")
		}
		return fmt.Errorf("program yönetici olarak başlatılamadı: %w", err)
	}
	return nil
}

// joinArgs builds a command line tail that CommandLineToArgvW (and Go's
// os.Args parsing) splits back into exactly args.
func joinArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	return strings.Join(quoted, " ")
}

// OpenURL opens a loopback http URL (e.g. the local panel) in the default
// browser. Any other scheme or host is refused.
func OpenURL(rawURL string) error {
	u, err := validateLoopbackURL(rawURL)
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return errors.New("geçersiz adres")
	}
	if err := windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("tarayıcı açılamadı: %w", err)
	}
	return nil
}

func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("program yolu bulunamadı: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Clean(exe), nil
}
