//go:build windows

package privsep

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// helperMemory caps the helper's committed memory (job object).
const helperMemory = 512 << 20

// helperAccount is unused on Windows: the restricted token is derived from
// the parent's own (Command).
func helperAccount() (uint32, uint32, error) { return 0, 0, nil }

// contain puts the helper into a job that kills it when the parent's handle
// closes (the parent exits or the helper is replaced), forbids it to start
// any other process and caps its memory. It runs before the first request
// is sent.
func contain(pid int) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
	info.BasicLimitInformation.ActiveProcessLimit = 1
	info.ProcessMemoryLimit = helperMemory
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("iş nesnesi sınırları: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid)) //nolint:gosec // a process id
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	defer windows.CloseHandle(proc)
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("iş nesnesine eklenemedi: %w", err)
	}
	return func() { windows.CloseHandle(job) }, nil
}

// confine describes the sandbox: Enter already checked the low integrity
// level; the token's restricting SIDs and the job come from the parent.
func confine() string {
	return "düşük bütünlük, kısıtlayıcı SID'ler (Everyone, Users, RESTRICTED), yönetici grubu yalnızca reddetme, iş nesnesi (tek süreç, 512 MB)"
}
