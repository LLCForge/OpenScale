package panel

import (
	"math"
	"slices"
	"sort"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Security score (#238). Every check is local: the signed document, the
// owner's backup list, the system reports devices sent through the tunnel
// and, in the desktop app, this computer's own settings. Nothing is sent
// anywhere. The panel words each check from its ID, so the score speaks
// every panel language; the server only reports facts.

// Check results.
const (
	checkPass = "pass"
	checkWarn = "warn"
	checkFail = "fail"
	// checkSkip: the check does not apply (no exit node in use, CLI panel
	// without this computer's view); it does not count toward the score.
	checkSkip = "skip"
)

// Check IDs. They are stable: the panel looks up its texts by them.
const (
	scoreBackup          = "backup"
	scoreBackupAge       = "backup_age"
	scoreDocumentExpiry  = "document_expiry"
	scoreWideRule        = "wide_rule"
	scoreUnusedTags      = "unused_tags"
	scoreExitUsers       = "exit_users"
	scoreOutdated        = "outdated_devices"
	scoreExpiringMembers = "expiring_members"
	scoreKillSwitch      = "kill_switch"
	scoreRemoteDesktop   = "remote_desktop"
	scoreSSH             = "ssh"
	scoreOpenPorts       = "open_ports"
	scorePostQuantum     = "post_quantum"
)

// backupMaxAge is when an old backup is worth renewing: the passphrase or
// the medium it sits on may be forgotten or broken by then.
const backupMaxAge = 365 * 24 * time.Hour

// maxScoreNames bounds the names listed in one check.
const maxScoreNames = 20

type scoreCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Weight int    `json:"weight"`
	// Count, Days and Names fill the check's text, for example "3 kural".
	Count int      `json:"count,omitempty"`
	Days  int      `json:"days,omitempty"`
	Names []string `json:"names,omitempty"`
}

type scoreReport struct {
	// Score is 0-100: passed weight plus half of the warned weight, over
	// the weight of the checks that apply.
	Score int `json:"score"`
	// Grade is excellent (90+), good (70+), fair (50+) or weak.
	Grade  string       `json:"grade"`
	Checks []scoreCheck `json:"checks"`
	// Local reports whether this computer's own checks were included.
	Local     bool      `json:"local"`
	CheckedAt time.Time `json:"checkedAt"`
}

type scoreInput struct {
	Doc         *trust.Document
	BackupCount int
	LastBackup  time.Time
	Now         time.Time
	// Outdated lists devices whose OpenScale is older than the panel's.
	Outdated []string
	// Device is this computer's tunnel; nil for the CLI panel.
	Device *DeviceStatus
	// Local is this computer's exposure check; nil when unknown.
	Local *LocalSecurity
}

// wideRule reports an enabled allow rule from every device to every device
// on every port; the same test guards "rule add" on the command line.
func wideRule(r trust.Rule) bool {
	if r.Disabled || r.IsDeny() || r.Service != "" {
		return false
	}
	return slices.Contains(r.From, "*") && slices.Contains(r.To, "*") &&
		(r.Protocol == trust.ProtocolAny || len(r.Ports) == 0 || slices.Contains(r.Ports, "*") || slices.Contains(r.Ports, "1-65535"))
}

func limitNames(names []string) []string {
	sort.Strings(names)
	if len(names) > maxScoreNames {
		names = names[:maxScoreNames]
	}
	return names
}

// computeScore runs every check. It is pure so tests can cover each case.
func computeScore(in scoreInput) scoreReport {
	doc := in.Doc
	var checks []scoreCheck
	add := func(c scoreCheck) { checks = append(checks, c) }

	// Root key backup: without one, a broken disk loses the network.
	switch {
	case in.BackupCount == 0:
		add(scoreCheck{ID: scoreBackup, Status: checkFail, Weight: 25})
	default:
		add(scoreCheck{ID: scoreBackup, Status: checkPass, Weight: 25, Count: in.BackupCount})
		age := in.Now.Sub(in.LastBackup)
		c := scoreCheck{ID: scoreBackupAge, Status: checkPass, Weight: 5, Days: int(age.Hours() / 24)}
		if !in.LastBackup.IsZero() && age > backupMaxAge {
			c.Status = checkWarn
		}
		add(c)
	}

	// Document validity: an expired document stops new connections.
	days := daysUntil(in.Now, doc.ExpiresAt)
	expiry := scoreCheck{ID: scoreDocumentExpiry, Status: checkPass, Weight: 10, Days: days}
	switch {
	case days <= 0:
		expiry.Status = checkFail
	case days <= 14:
		expiry.Status = checkWarn
	}
	add(expiry)

	// Every device to every device on every port defeats the rules.
	wide := 0
	for _, r := range doc.Rules {
		if wideRule(r) {
			wide++
		}
	}
	wc := scoreCheck{ID: scoreWideRule, Status: checkPass, Weight: 15, Count: wide}
	if wide > 0 {
		wc.Status = checkFail
	}
	add(wc)

	unused := doc.TagUsage()
	uc := scoreCheck{ID: scoreUnusedTags, Status: checkPass, Weight: 5, Count: len(unused)}
	if len(unused) > 0 {
		uc.Status, uc.Names = checkWarn, limitNames(append([]string{}, unused...))
	}
	add(uc)

	exitNodes := 0
	for _, d := range doc.Devices {
		if d.HasRole(trust.RoleExitNode) {
			exitNodes++
		}
	}
	ec := scoreCheck{ID: scoreExitUsers, Status: checkSkip, Weight: 5, Count: exitNodes}
	if exitNodes > 0 {
		ec.Status = checkPass
		if doc.ExitUsers == nil {
			ec.Status = checkWarn
		}
	}
	add(ec)

	oc := scoreCheck{ID: scoreOutdated, Status: checkPass, Weight: 10, Count: len(in.Outdated)}
	if len(in.Outdated) > 0 {
		oc.Status, oc.Names = checkWarn, limitNames(append([]string{}, in.Outdated...))
	}
	add(oc)

	var expiring []string
	for _, d := range doc.Devices {
		if daysUntil(in.Now, d.ExpiresAt) <= 14 {
			expiring = append(expiring, d.Name)
		}
	}
	mc := scoreCheck{ID: scoreExpiringMembers, Status: checkPass, Weight: 5, Count: len(expiring)}
	if len(expiring) > 0 {
		mc.Status, mc.Names = checkWarn, limitNames(expiring)
	}
	add(mc)

	// This computer (desktop app only).
	ks := scoreCheck{ID: scoreKillSwitch, Status: checkSkip, Weight: 10}
	pq := scoreCheck{ID: scorePostQuantum, Status: checkSkip, Weight: 5}
	if dev := in.Device; dev != nil {
		if dev.ExitNode != "" || dev.ExitNodeWanted != "" {
			switch {
			case dev.KillSwitch && dev.KillSwitchError != "":
				ks.Status = checkFail
			case dev.KillSwitch:
				ks.Status = checkPass
			default:
				ks.Status = checkWarn
			}
		}
		pq.Status = checkWarn
		if dev.Transport.PostQuantum {
			pq.Status = checkPass
		}
	}
	add(ks)
	add(pq)

	rdp := scoreCheck{ID: scoreRemoteDesktop, Status: checkSkip, Weight: 15}
	ssh := scoreCheck{ID: scoreSSH, Status: checkSkip, Weight: 10}
	ports := scoreCheck{ID: scoreOpenPorts, Status: checkSkip, Weight: 5}
	if sec := in.Local; sec != nil && sec.Supported && sec.Error == "" {
		rdp.Status = exposureStatus(sec.RDP)
		ssh.Status = exposureStatus(sec.SSH)
		ports.Status, ports.Count = checkPass, sec.Summary.All
		if sec.Summary.All > 0 {
			ports.Status = checkWarn
		}
	}
	add(rdp)
	add(ssh)
	add(ports)

	rep := scoreReport{Checks: checks, Local: in.Device != nil || in.Local != nil, CheckedAt: in.Now.UTC()}
	total, earned := 0.0, 0.0
	for _, c := range checks {
		switch c.Status {
		case checkPass:
			total += float64(c.Weight)
			earned += float64(c.Weight)
		case checkWarn:
			total += float64(c.Weight)
			earned += float64(c.Weight) / 2
		case checkFail:
			total += float64(c.Weight)
		}
	}
	rep.Score = 100
	if total > 0 {
		rep.Score = int(math.Round(100 * earned / total))
	}
	switch {
	case rep.Score >= 90:
		rep.Grade = "excellent"
	case rep.Score >= 70:
		rep.Grade = "good"
	case rep.Score >= 50:
		rep.Grade = "fair"
	default:
		rep.Grade = "weak"
	}
	return rep
}

// exposureStatus grades RDP or SSH: off or limited to OpenScale passes,
// reachable from the LAN or the internet fails.
func exposureStatus(a ServiceAccess) string {
	if !a.Available || a.OverlayOnly {
		return checkPass
	}
	return checkFail
}
