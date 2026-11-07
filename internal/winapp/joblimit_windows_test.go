//go:build windows

package winapp

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The test process puts itself into a job with a generous ceiling and
// reads the limit back from the job.
func TestLimitServiceResourcesAppliesJob(t *testing.T) {
	got := LimitServiceResources(ResourceLimits{MemoryMax: 8 << 30})
	if !got.Applied {
		t.Skipf("job object not available here: %s", got.Error)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(serviceJob, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		t.Fatal(err)
	}
	if info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY == 0 || uint64(info.ProcessMemoryLimit) != 8<<30 {
		t.Fatalf("limit not set: flags=%#x mem=%d", info.BasicLimitInformation.LimitFlags, info.ProcessMemoryLimit)
	}
	if cur, ok := CurrentResourceLimits(); !ok || !cur.Applied {
		t.Fatalf("not recorded: %+v", cur)
	}
}
