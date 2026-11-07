//go:build linux

package tpm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
)

// Linux: the kernel's resource manager device /dev/tpmrm0 (ADR-0124).

const (
	rmDevice     = "/dev/tpmrm0"
	versionMajor = "/sys/class/tpm/tpm0/tpm_version_major"
)

// Detect checks for the resource-managed TPM device. It sends no command.
func Detect() (Presence, error) {
	if _, err := os.Stat(rmDevice); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Presence{}, nil
		}
		return Presence{}, err
	}
	p := Presence{Present: true, Interface: rmDevice}
	if data, err := os.ReadFile(versionMajor); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "2":
			p.Version = "2.0"
		case "1":
			p.Version = "1.2"
		}
	}
	return p, nil
}

type devTransport struct {
	mu sync.Mutex
	f  *os.File
}

// Open returns a read-only transport to /dev/tpmrm0.
func Open() (Transport, error) {
	f, err := os.OpenFile(rmDevice, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("open %s: %w", rmDevice, err)
	}
	return ReadOnly(&devTransport{f: f}), nil
}

func (t *devTransport) Submit(cmd []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil, errors.New("TPM device is closed")
	}
	if _, err := t.f.Write(cmd); err != nil {
		return nil, fmt.Errorf("write TPM command: %w", err)
	}
	out := make([]byte, MaxResponse)
	n, err := t.f.Read(out)
	if err != nil {
		return nil, fmt.Errorf("read TPM response: %w", err)
	}
	return out[:n], nil
}

func (t *devTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f = nil
	return err
}
