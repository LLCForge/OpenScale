package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/winapp"
)

// Start-up protections of the desktop and service processes (G4,
// ADR-0195):
//   - process mitigation policies by command (#642), right after the DLL
//     search hardening and before any other DLL is loaded;
//   - the installed program folder must hold no foreign DLL or dylib and
//     be writable only by administrators (#644), for the service and the
//     tray;
//   - the service checks its own signature and the signed manifest of the
//     last update before it opens the tunnel (#607).
//
// The checks that block print the reason and exit with code 1 before any
// key is read.

const exitStartupBlocked = 1

// applyMitigations adds the policy results to the hardening report.
func applyMitigations(args []string, st *privacy.HardeningStatus) winapp.MitigationProfile {
	profile := winapp.MitigationProfileFor(args)
	for _, r := range winapp.ApplyMitigations(profile) {
		if r.Applied {
			st.Measures = append(st.Measures, "süreç politikası: "+r.Name)
		} else if r.Err != "" {
			st.Warnings = append(st.Warnings, "süreç politikası uygulanamadı: "+r.Name+" ("+r.Err+")")
		}
	}
	return profile
}

// startupChecks runs the blocking checks for the profile. It returns
// false when the program must exit.
func startupChecks(profile winapp.MitigationProfile, stderr io.Writer, now time.Time) bool {
	if profile != winapp.ProfileService && profile != winapp.ProfileTray {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		return true
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	if rep := winapp.CheckProgramFolder(exe, winapp.InstalledProgramDirs()); rep.Block() {
		fmt.Fprintf(stderr, "hata: %v\n", rep.Err())
		return false
	}
	if profile != winapp.ProfileService || updater.SelfVerifyDisabled() {
		return true
	}
	verdict, ok := updater.VerifyRunningService(now)
	if ok && verdict.Block {
		fmt.Fprintf(stderr, "hata: %v\n", verdict.Err())
		fmt.Fprintf(stderr, "Kurtarma: programı imzalı sürümden yeniden kurun (geçici olarak %s=off ile denetim atlanır).\n", updater.SelfVerifyEnv)
		return false
	}
	return true
}

// readSecretSecure reads a passphrase on the separate desktop when
// OPENSCALE_SECURE_INPUT=desktop (#649). ok is false when the terminal
// prompt should be used instead. The result leaves locked memory here
// because the CLI takes a []byte; the CLI wipes it after use.
func readSecretSecure(prompt string) ([]byte, bool, error) {
	if !winapp.SecureInputRequested() {
		return nil, false, nil
	}
	buf, err := winapp.ReadSecretSecureDesktop(prompt)
	if errors.Is(err, winapp.ErrSecureInputUnavailable) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	defer buf.Destroy()
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, true, nil
}
