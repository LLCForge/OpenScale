//go:build windows

package winapp

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROCESS_MITIGATION_POLICY values used here.
const (
	processDynamicCodePolicy     = 2
	processExtensionPointDisable = 6
	processSignaturePolicy       = 8
	processImageLoadPolicy       = 10
	imageLoadNoRemote            = 1 << 0
	imageLoadNoLowMandatoryLabel = 1 << 1
	imageLoadPreferSystem32      = 1 << 2
	dynamicCodeProhibit          = 1 << 0
	extensionPointDisable        = 1 << 0
	signatureMicrosoftSignedOnly = 1 << 0
)

var procSetProcessMitigationPolicy = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetProcessMitigationPolicy")

func setPolicy(policy uintptr, flags uint32) error {
	if err := procSetProcessMitigationPolicy.Find(); err != nil {
		return err
	}
	r, _, err := procSetProcessMitigationPolicy.Call(policy, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
	if r == 0 {
		return err
	}
	return nil
}

func applyMitigations(s mitigationSet) []MitigationResult {
	var out []MitigationResult
	add := func(name string, policy uintptr, flags uint32) {
		err := setPolicy(policy, flags)
		r := MitigationResult{Name: name, Applied: err == nil}
		if err != nil {
			r.Err = err.Error()
		}
		out = append(out, r)
	}
	if s.imageLoad {
		flags := uint32(imageLoadNoRemote | imageLoadNoLowMandatoryLabel)
		if s.preferSystem32 {
			flags |= imageLoadPreferSystem32
		}
		add("uzak ve düşük bütünlüklü DLL yükleme yasağı", processImageLoadPolicy, flags)
	}
	if s.noExtensionPoint {
		add("eski uzantı noktaları kapalı (AppInit, kancalar)", processExtensionPointDisable, extensionPointDisable)
	}
	if s.microsoftSigned {
		add("yalnızca Microsoft imzalı DLL", processSignaturePolicy, signatureMicrosoftSignedOnly)
	}
	// Last: it also forbids changing executable memory, so it goes after
	// every other call that might need that.
	if s.noDynamicCode {
		add("dinamik kod yasağı", processDynamicCodePolicy, dynamicCodeProhibit)
	}
	return out
}
