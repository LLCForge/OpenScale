package winapp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Daemon resource limits (#494). On Windows the service puts itself into
// a job object with a committed memory ceiling (and, when asked, a hard
// CPU cap), so a leak ends in a service restart through the recovery
// actions instead of a machine that swaps itself to a halt. Linux uses the
// systemd unit (MemoryHigh, MemoryMax, TasksMax in deploy/linux).

// Environment variables that override the defaults. The service reads
// its environment from the registry (the service key's Environment value),
// so they are an expert setting.
const (
	EnvServiceMemoryMax = "OPENSCALE_SERVICE_MEMORY_MAX"
	EnvServiceCPUMax    = "OPENSCALE_SERVICE_CPU_MAX"
)

// DefaultServiceMemoryMax is far above normal use (tens of MiB) and far
// below what would hurt a computer.
const DefaultServiceMemoryMax = 1 << 30

// Bounds of the settings.
const (
	MinServiceMemoryMax = 64 << 20
	MaxServiceMemoryMax = 64 << 30
)

// ResourceLimits are the limits of the service process. Zero means none.
type ResourceLimits struct {
	MemoryMax uint64 `json:"memory_max,omitempty"`
	// CPUPercent is a hard cap of the whole machine's CPU time, 1-100.
	CPUPercent int `json:"cpu_percent,omitempty"`
	// Applied is true once the limits are in force.
	Applied bool `json:"applied,omitempty"`
	// Error tells why they are not.
	Error string `json:"error,omitempty"`
}

// ParseResourceLimits reads the overrides; unset gives the defaults.
func ParseResourceLimits(getenv func(string) string) (ResourceLimits, error) {
	l := ResourceLimits{MemoryMax: DefaultServiceMemoryMax}
	if v := strings.TrimSpace(getenv(EnvServiceMemoryMax)); v != "" {
		n, err := ParseByteSize(v)
		if err != nil {
			return ResourceLimits{}, fmt.Errorf("%s: %w", EnvServiceMemoryMax, err)
		}
		if n != 0 && (n < MinServiceMemoryMax || n > MaxServiceMemoryMax) {
			return ResourceLimits{}, fmt.Errorf("%s: 0 (sınırsız) ya da 64MiB ile 64GiB arasında olmalı", EnvServiceMemoryMax)
		}
		l.MemoryMax = n
	}
	if v := strings.TrimSpace(getenv(EnvServiceCPUMax)); v != "" {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "%"))
		if err != nil || n < 0 || n > 100 {
			return ResourceLimits{}, fmt.Errorf("%s: 0 (sınırsız) ile 100 arasında bir yüzde olmalı", EnvServiceCPUMax)
		}
		if n == 100 {
			n = 0
		}
		l.CPUPercent = n
	}
	return l, nil
}

// ParseByteSize reads "512MiB", "1GiB", "64M", "1073741824" or "0".
func ParseByteSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mul    uint64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}}
	mul := uint64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mul = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mul
			break
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("boyut geçersiz (ör. 512MiB, 1GiB)")
	}
	if n > (1<<63)/mul {
		return 0, errors.New("boyut çok büyük")
	}
	return n * mul, nil
}

var (
	limitsMu      sync.Mutex
	activeLimits  ResourceLimits
	limitsWereSet bool
)

// CurrentResourceLimits returns what the service applied, if anything.
func CurrentResourceLimits() (ResourceLimits, bool) {
	limitsMu.Lock()
	defer limitsMu.Unlock()
	return activeLimits, limitsWereSet
}

func recordLimits(l ResourceLimits) {
	limitsMu.Lock()
	activeLimits, limitsWereSet = l, true
	limitsMu.Unlock()
}
