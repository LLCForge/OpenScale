package panel

import (
	"context"
	"io"
	"time"
)

// Folder sync, encrypted backup and the offline outbox (ADR-0104,
// ADR-0110).

// SyncFolderView is one synchronized folder of this computer.
type SyncFolderView struct {
	ID               string   `json:"id"`
	Path             string   `json:"path"`
	Mode             string   `json:"mode"`
	Peers            []string `json:"peers"`
	PropagateDeletes bool     `json:"propagateDeletes"`
	Versions         int      `json:"versions"`
	// ServedTo lists the devices the rules let read this folder here.
	ServedTo []string `json:"servedTo"`
	// Readable lists the listed peers that let this computer pull.
	Readable  []string   `json:"readable"`
	LastPull  *time.Time `json:"lastPull,omitempty"`
	LastError string     `json:"lastError,omitempty"`
	Fetched   int        `json:"fetched"`
	Deleted   int        `json:"deleted"`
	Conflicts int        `json:"conflicts"`
	Failed    int        `json:"failed"`
}

// SyncBackupView is the backup schedule of this computer.
type SyncBackupView struct {
	Enabled       bool     `json:"enabled"`
	Target        string   `json:"target"`
	Folders       []string `json:"folders"`
	IntervalHours int      `json:"intervalHours"`
	// KeyFingerprint identifies the backup key without revealing it;
	// KeyExported says the owner saved a passphrase-protected copy, which
	// backups require.
	KeyFingerprint string     `json:"keyFingerprint"`
	KeyExported    bool       `json:"keyExported"`
	KeyExportedAt  *time.Time `json:"keyExportedAt,omitempty"`
	LastRun        *time.Time `json:"lastRun,omitempty"`
	LastError      string     `json:"lastError,omitempty"`
	LastSnapshot   string     `json:"lastSnapshot,omitempty"`
}

// OutboxView is one file waiting for its recipient.
type OutboxView struct {
	ID        string    `json:"id"`
	Peer      string    `json:"peer"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Strip     string    `json:"strip"`
	Queued    time.Time `json:"queued"`
	Attempts  int       `json:"attempts"`
	NextTry   time.Time `json:"nextTry"`
	LastError string    `json:"lastError,omitempty"`
}

// SyncStatus is the sync page.
type SyncStatus struct {
	Hosted      bool             `json:"hosted"`
	Running     bool             `json:"running"`
	Error       string           `json:"error"`
	IntervalSec int              `json:"intervalSec"`
	Folders     []SyncFolderView `json:"folders"`
	Backup      SyncBackupView   `json:"backup"`
	// BackupTargets are devices whose rules accept backups from here.
	BackupTargets []string     `json:"backupTargets"`
	Outbox        []OutboxView `json:"outbox"`
}

// SyncFolderChange adds or replaces a folder.
type SyncFolderChange struct {
	ID               string   `json:"id"`
	Path             string   `json:"path"`
	Mode             string   `json:"mode"`
	Peers            []string `json:"peers"`
	PropagateDeletes bool     `json:"propagateDeletes"`
	Versions         int      `json:"versions"`
}

// SyncBackupChange sets the backup schedule.
type SyncBackupChange struct {
	Enabled       bool     `json:"enabled"`
	Target        string   `json:"target"`
	Folders       []string `json:"folders"`
	IntervalHours int      `json:"intervalHours"`
}

// SyncVersionView is one kept earlier version of a file.
type SyncVersionView struct {
	Path   string    `json:"path"`
	Stored string    `json:"stored"`
	Time   time.Time `json:"time"`
	Size   int64     `json:"size"`
}

// SyncSnapshotView is one backup snapshot on the target.
type SyncSnapshotView struct {
	Folder string    `json:"folder"`
	Name   string    `json:"name"`
	Time   time.Time `json:"time"`
}

// SyncControl is implemented by the desktop service.
type SyncControl interface {
	SyncStatus() SyncStatus
	SetSyncFolder(c SyncFolderChange) error
	RemoveSyncFolder(id string) error
	SyncNow(ctx context.Context) error
	SyncVersions(id string) ([]SyncVersionView, error)
	RestoreSyncVersion(id, stored string) error
	SetSyncBackup(c SyncBackupChange) error
	// ExportBackupKey wraps the backup key with passphrase; once the owner
	// downloaded it, backups may run.
	ExportBackupKey(passphrase []byte) (string, error)
	BackupNow(ctx context.Context) error
	BackupSnapshots(ctx context.Context) ([]SyncSnapshotView, error)
	// QueueFile stores an upload and sends it when the recipient is
	// reachable (#140); strip is "", "location" or "all" (#139).
	QueueFile(device, name string, body io.Reader, size int64, strip string) (string, error)
	RemoveOutbox(id string) error
}
