//go:build windows

package winapp

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestServiceStartsAtBoot(t *testing.T) {
	if serviceStartType != mgr.StartAutomatic {
		t.Fatalf("service start type = %d, want automatic", serviceStartType)
	}
	// Read-only: when the service is installed on this computer, its
	// configuration must say automatic as well.
	m, err := mgr.Connect()
	if err != nil {
		t.Skipf("service manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("OpenScale service not installed here")
	}
	if err != nil {
		t.Skipf("open service: %v", err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		t.Skipf("config: %v", err)
	}
	if cfg.StartType != mgr.StartAutomatic {
		t.Fatalf("installed service start type = %d", cfg.StartType)
	}
}

func TestGetRunEntryReadOnly(t *testing.T) {
	// Reading the user's own Run key changes nothing.
	v, ok, err := GetRunEntry(false)
	if err != nil {
		t.Fatal(err)
	}
	if ok && RunCommandProgram(v) == "" {
		t.Logf("existing Run value is not in OpenScale's form: %q", v)
	}
}
