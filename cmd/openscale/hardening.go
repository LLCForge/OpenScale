package main

import (
	"github.com/openscale/openscale/internal/cli"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/winapp"
)

// hardenProcess turns off crash dumps before any key is read (#45): every
// command, the Windows service ("service run") and the coordinator are
// this one program. The status goes to the privacy report; a failure is
// not fatal because the measure is defence in depth.
func hardenProcess(args []string) winapp.MitigationProfile {
	// DLL search first, before anything loads a DLL by name (#518).
	dllMeasures, dllWarnings := privacy.HardenDLLSearch()
	st := privacy.HardenProcess()
	st.Measures = append(st.Measures, dllMeasures...)
	st.Warnings = append(st.Warnings, dllWarnings...)
	// Mitigation policies by command (#642, g4_startup.go).
	profile := applyMitigations(args, &st)
	cli.SetProcessHardening(st)
	// Known answer tests before any key is read (#531): a broken
	// primitive stops every command (selftest.go).
	cryptoSelfTestOrExit()
	return profile
}
