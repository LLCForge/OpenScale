package winapp

import (
	"os"
	"strings"
)

// Process mitigation policies (#642, ADR-0195 section 4). Every OpenScale
// process applies the strongest set its job allows, chosen by command:
//
//	service   ("service run", "up", "coordinator run", "portable",
//	           "rdesk-helper"): no dynamic code, no legacy extension
//	           points (AppInit DLLs, global hooks, LSPs), images only from
//	           local, non-low-integrity files, System32 first. Not
//	           "Microsoft-signed DLLs only": wintun.dll is signed by
//	           WireGuard LLC.
//	tray      ("app", "autostart run"): as service.
//	window    ("panel-window", "window"): images only from local files,
//	           System32 first. The web engine needs dynamic code (its
//	           JavaScript compiler), child processes and extension points.
//	secret    (commands that read the root key or a device key: network,
//	           key, device, bundle, invite, keygen, join, panel, group,
//	           rule, exit users, coordinator keygen): as service plus
//	           Microsoft-signed DLLs only, so an injected or planted DLL
//	           cannot read the passphrase.
//	cli       (everything else): as service. Some of these query the
//	           Wintun driver, so no signer restriction.
//
// Control Flow Guard and CET shadow stacks cannot be switched on at run
// time; they need image flags the Go linker does not write (see the ADR).
// Child process creation is not forbidden in any profile, because the
// service starts netsh and the tray starts the window process.
// OPENSCALE_MITIGATIONS=off skips everything (for diagnosing a third-party
// DLL that the policies block).

// MitigationProfile selects the policy set.
type MitigationProfile string

const (
	ProfileService MitigationProfile = "service"
	ProfileTray    MitigationProfile = "tray"
	ProfileWindow  MitigationProfile = "window"
	ProfileCLI     MitigationProfile = "cli"
	ProfileSecret  MitigationProfile = "secret"
)

// MitigationsEnv set to "off" disables the policies.
const MitigationsEnv = "OPENSCALE_MITIGATIONS"

// MitigationResult reports one policy.
type MitigationResult struct {
	Name    string
	Applied bool
	Err     string
}

// MitigationProfileFor picks the profile of a command line (os.Args[1:]).
func MitigationProfileFor(args []string) MitigationProfile {
	args = skipGlobalFlags(args)
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		// An unknown leading option: the safe set without
		// "Microsoft-signed only", which would break wintun.dll.
		return ProfileService
	}
	words := strings.Join(firstWords(args, 2), " ")
	switch {
	case words == "service run", words == "coordinator run",
		len(args) > 0 && (args[0] == "up" || args[0] == "portable" || args[0] == "rdesk-helper"):
		return ProfileService
	case len(args) == 0, args[0] == "app", words == "autostart run":
		return ProfileTray
	case args[0] == "panel-window", args[0] == "window":
		return ProfileWindow
	case secretCommand(args[0], words):
		return ProfileSecret
	}
	return ProfileCLI
}

// secretCommand reports whether a command reads a private key.
func secretCommand(first, words string) bool {
	switch first {
	case "network", "key", "device", "bundle", "invite", "keygen", "join", "invite-join", "panel", "group", "rule":
		return true
	}
	return words == "coordinator keygen" || strings.HasPrefix(words, "exit users")
}

func firstWords(args []string, n int) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || len(out) == n {
			break
		}
		out = append(out, a)
	}
	return out
}

// mitigationSet is what a profile asks for.
type mitigationSet struct {
	noDynamicCode    bool
	noExtensionPoint bool
	imageLoad        bool
	preferSystem32   bool
	microsoftSigned  bool
}

func (p MitigationProfile) set() mitigationSet {
	switch p {
	case ProfileService, ProfileTray:
		return mitigationSet{noDynamicCode: true, noExtensionPoint: true, imageLoad: true, preferSystem32: true}
	case ProfileWindow:
		return mitigationSet{imageLoad: true, preferSystem32: true}
	case ProfileCLI:
		return mitigationSet{noDynamicCode: true, noExtensionPoint: true, imageLoad: true, preferSystem32: true}
	case ProfileSecret:
		return mitigationSet{noDynamicCode: true, noExtensionPoint: true, imageLoad: true, preferSystem32: true, microsoftSigned: true}
	}
	return mitigationSet{}
}

// MitigationsDisabled reports whether the owner turned the policies off.
func MitigationsDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(MitigationsEnv)), "off")
}

// ApplyMitigations applies the profile to this process. It is best
// effort: an older Windows refuses some policies, which are then
// reported, not fatal. On other systems it does nothing.
func ApplyMitigations(p MitigationProfile) []MitigationResult {
	if MitigationsDisabled() {
		return []MitigationResult{{Name: "süreç azaltma politikaları", Err: MitigationsEnv + "=off"}}
	}
	return applyMitigations(p.set())
}

// skipGlobalFlags drops the leading global options of the CLI (--network
// and --format, with their values).
func skipGlobalFlags(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--network" || a == "-network" || a == "--format" || a == "-format":
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
		case strings.HasPrefix(a, "--network=") || strings.HasPrefix(a, "-network=") ||
			strings.HasPrefix(a, "--format=") || strings.HasPrefix(a, "-format="):
			args = args[1:]
		default:
			return args
		}
	}
	return args
}
