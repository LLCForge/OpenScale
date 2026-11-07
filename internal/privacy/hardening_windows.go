//go:build windows

package privacy

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procGetErrorMode = modKernel32.NewProc("GetErrorMode")
	procWerGetFlags  = modKernel32.NewProc("WerGetFlags")
	procWerSetFlags  = modKernel32.NewProc("WerSetFlags")
)

const (
	semFailCriticalErrors = 0x0001
	semNoGPFaultErrorBox  = 0x0002
	semNoOpenFileErrorBox = 0x8000
	// werNoHeap keeps the heap out of any report Windows Error Reporting
	// still makes (WER_FAULT_REPORTING_FLAG_NOHEAP).
	werNoHeap = 0x0001
	// werNoUI is WER_FAULT_REPORTING_NO_UI.
	werNoUI = 0x0020
)

// hardenProcess keeps Windows Error Reporting away from this process: the
// error mode bit SEM_NOGPFAULTERRORBOX stops WER from handling a crash
// (the Go runtime sets it too, unless GOTRACEBACK=wer), and if WER runs
// anyway its report leaves out the heap, where keys live. Both are
// per-process; the machine-wide WER LocalDumps setting is not touched.
func hardenProcess() HardeningStatus {
	var st HardeningStatus
	mode := uint32(semFailCriticalErrors | semNoGPFaultErrorBox | semNoOpenFileErrorBox)
	if r, _, _ := procGetErrorMode.Call(); r != 0 {
		mode |= uint32(r)
	}
	windows.SetErrorMode(mode)
	if currentErrorMode()&semNoGPFaultErrorBox != 0 {
		st.CoreDumpsDisabled = true
		st.Measures = append(st.Measures, "SetErrorMode(SEM_NOGPFAULTERRORBOX): Windows Hata Bildirimi bu süreci ele almaz")
	} else {
		st.Warnings = append(st.Warnings, "SetErrorMode uygulanamadı")
	}
	if err := procWerSetFlags.Find(); err != nil {
		st.Warnings = append(st.Warnings, "WerSetFlags bulunamadı")
		return st
	}
	var flags uint32
	_, _, _ = procWerGetFlags.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&flags)))
	if hr, _, _ := procWerSetFlags.Call(uintptr(flags | werNoHeap | werNoUI)); hr == 0 {
		st.Measures = append(st.Measures, "WerSetFlags(NOHEAP): olası bir hata raporu yığın belleği içermez")
	} else {
		st.Warnings = append(st.Warnings, "WerSetFlags uygulanamadı")
	}
	return st
}

// currentErrorMode returns the process error mode.
func currentErrorMode() uint32 {
	r, _, _ := procGetErrorMode.Call()
	return uint32(r)
}

// werFlags returns the WER flags of this process (tests).
func werFlags() (uint32, bool) {
	var flags uint32
	hr, _, _ := procWerGetFlags.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&flags)))
	return flags, hr == 0
}
