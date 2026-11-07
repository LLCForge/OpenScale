package winapp

import (
	"strings"
	"testing"
)

func TestParseResourceLimits(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, err := ParseResourceLimits(env(nil))
	if err != nil || l.MemoryMax != DefaultServiceMemoryMax || l.CPUPercent != 0 {
		t.Fatalf("defaults: %+v %v", l, err)
	}
	l, err = ParseResourceLimits(env(map[string]string{EnvServiceMemoryMax: "512MiB", EnvServiceCPUMax: "50%"}))
	if err != nil || l.MemoryMax != 512<<20 || l.CPUPercent != 50 {
		t.Fatalf("set: %+v %v", l, err)
	}
	l, err = ParseResourceLimits(env(map[string]string{EnvServiceMemoryMax: "0", EnvServiceCPUMax: "100"}))
	if err != nil || l.MemoryMax != 0 || l.CPUPercent != 0 {
		t.Fatalf("off: %+v %v", l, err)
	}
	for _, bad := range []map[string]string{
		{EnvServiceMemoryMax: "1MiB"},
		{EnvServiceMemoryMax: "çok"},
		{EnvServiceMemoryMax: "99999999999GiB"},
		{EnvServiceCPUMax: "101"},
		{EnvServiceCPUMax: "-1"},
	} {
		if _, err := ParseResourceLimits(env(bad)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestParseByteSize(t *testing.T) {
	for in, want := range map[string]uint64{"1GiB": 1 << 30, "64M": 64 << 20, "2048": 2048, " 3 KiB ": 3 << 10} {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v", in, got, err)
		}
	}
	if _, err := ParseByteSize("18446744073709551615GiB"); err == nil || !strings.Contains(err.Error(), "geçersiz") && !strings.Contains(err.Error(), "büyük") {
		t.Fatalf("overflow: %v", err)
	}
}
