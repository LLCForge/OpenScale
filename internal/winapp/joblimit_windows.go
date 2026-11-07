//go:build windows

package winapp

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobCPURateControl is JOBOBJECT_CPU_RATE_CONTROL_INFORMATION with the
// CpuRate member of its union (percent times 100).
type jobCPURateControl struct {
	ControlFlags uint32
	CPURate      uint32
}

const (
	jobCPURateEnable  = 0x1
	jobCPURateHardCap = 0x4
)

// serviceJob keeps the job handle open for the life of the process; the
// limits end with the handle.
var serviceJob windows.Handle

// LimitServiceResources puts this process into a new job object with the
// given limits. Without any limit it does nothing. The job does not kill
// on close and allows breakaway-free children (the remote desktop helper
// and netsh inherit the limits, which is intended).
func LimitServiceResources(l ResourceLimits) ResourceLimits {
	if l.MemoryMax == 0 && l.CPUPercent == 0 {
		recordLimits(l)
		return l
	}
	err := applyJobLimits(l)
	if err != nil {
		l.Error = err.Error()
	} else {
		l.Applied = true
	}
	recordLimits(l)
	return l
}

func applyJobLimits(l ResourceLimits) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("iş nesnesi oluşturulamadı: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(job)
		}
	}()
	if l.MemoryMax != 0 {
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(l.MemoryMax)
		if uint64(info.ProcessMemoryLimit) != l.MemoryMax {
			return fmt.Errorf("bellek sınırı bu mimaride çok büyük")
		}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			return fmt.Errorf("bellek sınırı konamadı: %w", err)
		}
	}
	if l.CPUPercent > 0 {
		info := jobCPURateControl{ControlFlags: jobCPURateEnable | jobCPURateHardCap, CPURate: uint32(l.CPUPercent) * 100}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			return fmt.Errorf("işlemci sınırı konamadı: %w", err)
		}
	}
	self, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("servis süreci açılamadı: %w", err)
	}
	defer windows.CloseHandle(self)
	if err := windows.AssignProcessToJobObject(job, self); err != nil {
		return fmt.Errorf("servis iş nesnesine alınamadı: %w", err)
	}
	ok = true
	serviceJob = job
	return nil
}
