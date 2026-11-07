// Package privsep is privilege separation (ADR-0109, ADR-0233, #161,
// #162): the parsing helper, the way it is started with fewer rights than
// its parent, and reporting what a process actually runs with.
//
// The tunnel, firewall and DNS work needs administrator or root rights;
// parsing input from the network does not. A Gate (gate.go) hands network
// documents and release manifests to a helper process (helper.go) over a
// framed stdin/stdout protocol (protocol.go) and fails closed: whatever the
// helper rejects, or fails to answer, is rejected. The helper is this
// program started with HelperArg through Command:
//
//   - Linux: the child is forked with the credentials of an unprivileged
//     account (Credential), a fresh session and a parent-death signal; it
//     calls Enter to set PR_SET_NO_NEW_PRIVS and to verify it cannot get
//     root back, then denies itself every file with Landlock and installs
//     a seccomp deny list (sandbox_linux.go).
//   - Windows: the child gets a restricted token (maximum privileges
//     removed, Administrators deny-only, restricting SIDs Everyone, Users
//     and RESTRICTED) at low integrity level and runs in a job object that
//     forbids child processes and caps memory (sandbox_windows.go). An
//     AppContainer needs a process attribute list that os/exec does not
//     offer; ADR-0233 explains why it is not needed for this helper.
//
// Nothing starts by itself: the service and "openscale up" create the
// gate, and the helper starts on the first request.
package privsep

import (
	"bufio"
	"strconv"
	"strings"
)

// Status describes the rights the current process runs with.
type Status struct {
	// Platform-neutral summary in Turkish.
	Summary string
	// NoNewPrivs is Linux's PR_SET_NO_NEW_PRIVS flag (false elsewhere).
	NoNewPrivs bool
	// Privileged is root (Linux: effective uid 0 or any effective
	// capability) or an elevated/high integrity token (Windows).
	Privileged bool
	// Integrity is the Windows integrity level name ("low", "medium",
	// "high", "system"); empty elsewhere.
	Integrity string
}

// procStatus holds the fields read from /proc/self/status.
type procStatus struct {
	noNewPrivs bool
	euid       int
	capEff     uint64
	ok         bool
}

// parseProcStatus reads Linux's /proc/self/status text.
func parseProcStatus(s string) procStatus {
	var ps procStatus
	seenUID := false
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		switch k {
		case "NoNewPrivs":
			ps.noNewPrivs = len(f) == 1 && f[0] == "1"
		case "Uid":
			if len(f) >= 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					ps.euid, seenUID = n, true
				}
			}
		case "CapEff":
			if len(f) == 1 {
				if n, err := strconv.ParseUint(f[0], 16, 64); err == nil {
					ps.capEff = n
				}
			}
		}
	}
	ps.ok = seenUID
	return ps
}

// integrityName maps a Windows mandatory label RID.
func integrityName(rid uint32) string {
	switch {
	case rid >= 0x4000:
		return "system"
	case rid >= 0x3000:
		return "high"
	case rid >= 0x2000:
		return "medium"
	case rid >= 0x1000:
		return "low"
	}
	return "untrusted"
}
