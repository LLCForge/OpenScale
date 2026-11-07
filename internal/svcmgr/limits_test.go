package svcmgr

import (
	"strings"
	"testing"
)

// Both services carry a memory ceiling and a task limit (#494, #484), so a
// leak restarts the service instead of exhausting the machine.
func TestUnitsHaveResourceLimits(t *testing.T) {
	for _, unit := range []string{"openscale-device.service", "openscale-coordinator.service"} {
		data, err := unitFiles.ReadFile("units/" + unit)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, key := range []string{"\nMemoryHigh=", "\nMemoryMax=", "\nTasksMax=", "\nEnvironment=GOMEMLIMIT="} {
			if strings.Count(text, key) != 1 {
				t.Errorf("%s: %s must appear exactly once", unit, strings.TrimSpace(key))
			}
		}
	}
}

func TestCgroupParsing(t *testing.T) {
	p, ok := cgroupV2Path([]byte("12:cpu:/x\n0::/system.slice/openscale-device.service\n"))
	if !ok || p != "/system.slice/openscale-device.service" {
		t.Fatalf("path %q %v", p, ok)
	}
	if _, ok := cgroupV2Path([]byte("0::/../../etc\n")); ok {
		t.Fatal("a path with .. accepted")
	}
	if _, ok := cgroupV2Path([]byte("1:name=systemd:/x\n")); ok {
		t.Fatal("cgroup v1 only must not report a path")
	}
	if parseCgroupValue([]byte("max\n")) != 0 || parseCgroupValue([]byte("268435456\n")) != 256<<20 || parseCgroupValue([]byte("x")) != 0 {
		t.Fatal("value parsing")
	}
}
