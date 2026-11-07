package trust

import (
	"errors"
	"fmt"
	"slices"
)

// Folder sync and backup rules (ADR-0104, ADR-0110).
//
// A sync rule grants the source read access to some of the destination's
// shared folders (folders) and/or lets the source keep encrypted backups
// on the destination (backup). Sync is pull only: no rule ever lets a
// device write into another device's folders. Backups stay append only
// unless allow_prune is set. Rules without these fields encode exactly as
// before, so documents without sync rules keep their bytes.

// ServiceSync is folder sync and the encrypted backup target (TCP 4050).
const ServiceSync RuleService = "sync"

// SyncPort is the folder sync service port (syncdir.DefaultPort).
// It was 4048 in ADR-0104; messaging (ADR-0109) took 4048 and the remote
// panel (ADR-0107) 4049, so sync moved to 4050 (ADR-0110).
const SyncPort uint16 = 4050

// Backup quota bounds.
const (
	// DefaultBackupQuota applies to a backup rule without quota.
	DefaultBackupQuota int64 = 50 << 30
	// MinBackupQuota and MaxBackupQuota bound an explicit quota.
	MinBackupQuota  int64 = 1 << 20
	MaxBackupQuota  int64 = 1 << 50
	maxSyncFolders        = 64
	maxSyncFolderID       = 63
)

// SyncGrant is what the sync rules give one device on another.
type SyncGrant struct {
	// Folders the source may read, sorted and without duplicates.
	Folders []string
	// Backup lets the source store encrypted backups.
	Backup bool
	// Quota is the largest quota of the matching backup rules.
	Quota int64
	// AllowPrune is true when a matching backup rule allows deleting.
	AllowPrune bool
}

// ValidSyncFolderID reports whether s is a folder ID a sync rule may list:
// lower case letters, digits and dashes, starting with a letter or digit,
// at most 63 characters (the same as syncdir.ValidID).
func ValidSyncFolderID(s string) bool {
	if s == "" || len(s) > maxSyncFolderID {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// hasSyncFields reports whether r sets a field only sync rules may set.
func (r Rule) hasSyncFields() bool {
	return len(r.Folders) != 0 || r.Backup || r.Quota != 0 || r.AllowPrune
}

func validateSyncRule(r Rule) error {
	if len(r.Folders) == 0 && !r.Backup {
		return errors.New("sync rules need folders or backup")
	}
	if !r.Backup && (r.Quota != 0 || r.AllowPrune) {
		return errors.New("quota and allow_prune need backup")
	}
	if r.Quota != 0 && (r.Quota < MinBackupQuota || r.Quota > MaxBackupQuota) {
		return fmt.Errorf("quota must be between %d and %d bytes", MinBackupQuota, MaxBackupQuota)
	}
	if len(r.Folders) > maxSyncFolders {
		return fmt.Errorf("sync rules list at most %d folders", maxSyncFolders)
	}
	seen := make(map[string]bool, len(r.Folders))
	for _, f := range r.Folders {
		if !ValidSyncFolderID(f) {
			return fmt.Errorf("invalid folder id %q", f)
		}
		if seen[f] {
			return fmt.Errorf("folders lists %q twice", f)
		}
		seen[f] = true
	}
	return nil
}

// AllowsSyncFolder reports whether device from may read the shared folder
// id of device to (pull it). A matching sync deny rule, or a packet deny
// rule over the service port, wins.
func (doc *Document) AllowsSyncFolder(from, to, id string) bool {
	if !ValidSyncFolderID(id) {
		return false
	}
	return doc.serviceAllowed(ServiceSync, from, to, func(r Rule) bool { return slices.Contains(r.Folders, id) })
}

// AllowsBackup reports whether device from may keep encrypted backups on
// device to.
func (doc *Document) AllowsBackup(from, to string) bool {
	return doc.serviceAllowed(ServiceSync, from, to, func(r Rule) bool { return r.Backup })
}

// SyncAccess combines every sync rule from device from to device to. The
// zero value grants nothing; any matching deny rule grants nothing.
func (doc *Document) SyncAccess(from, to string) SyncGrant {
	var g SyncGrant
	if !doc.serviceAllowed(ServiceSync, from, to, nil) {
		return g
	}
	src, dst := doc.subject(from), doc.subject(to)
	for _, r := range doc.Rules {
		if doc.ruleOff(r) || r.IsDeny() || r.Service != ServiceSync || !doc.matchesAny(r.From, src) || !doc.matchesAny(r.To, dst) {
			continue
		}
		for _, f := range r.Folders {
			if !slices.Contains(g.Folders, f) {
				g.Folders = append(g.Folders, f)
			}
		}
		if r.Backup {
			g.Backup = true
			q := r.Quota
			if q == 0 {
				q = DefaultBackupQuota
			}
			g.Quota = max(g.Quota, q)
			g.AllowPrune = g.AllowPrune || r.AllowPrune
		}
	}
	slices.Sort(g.Folders)
	return g
}
