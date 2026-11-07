package admin

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// BackupRecord is kept in backups.json so the owner is reminded when no
// backup exists. It deliberately stores no path or location.
type BackupRecord struct {
	CreatedAt time.Time `json:"created_at"`
	Label     string    `json:"label"`
}

const maxBackupLabel = 64

// CreateBackup re-encrypts the root key under a different passphrase and
// returns the sealed key file contents. The caller decides where it goes
// (a file on removable media, a browser download).
func (n *Network) CreateBackup(current, backupPassphrase []byte, label string, now time.Time) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(label) > maxBackupLabel {
		return nil, errors.New("backup label is too long")
	}
	if subtle.ConstantTimeCompare(current, backupPassphrase) == 1 {
		return nil, ErrSamePassphrase
	}
	if err := trust.CheckPassphrase(backupPassphrase); err != nil {
		return nil, err
	}
	rootPriv, err := n.sealed.Open(current)
	if err != nil {
		return nil, err
	}
	defer wipe(rootPriv)
	sealed, err := trust.SealRootKey(rootPriv, backupPassphrase, n.argon, n.random)
	if err != nil {
		return nil, err
	}
	data, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return nil, err
	}
	records, err := n.backupsLocked()
	if err != nil {
		return nil, err
	}
	if len(records) >= maxBackups {
		records = records[1:]
	}
	records = append(records, BackupRecord{CreatedAt: now.UTC().Truncate(time.Second), Label: label})
	encoded, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := securefile.Replace(filepath.Join(n.dir, backupsFile), encoded); err != nil {
		return nil, fmt.Errorf("write backup record: %w", err)
	}
	return data, nil
}

// Backups lists recorded backups.
func (n *Network) Backups() ([]BackupRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.backupsLocked()
}

func (n *Network) backupsLocked() ([]BackupRecord, error) {
	data, err := securefile.ReadPrivate(filepath.Join(n.dir, backupsFile), 256*1024)
	if errors.Is(err, fs.ErrNotExist) {
		return []BackupRecord{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backup records: %w", err)
	}
	var records []BackupRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode backup records: %w", err)
	}
	return records, nil
}

// Restore installs a backup copy as the root key of the network in dir
// after checking that it can be opened and that it signed the document.
// The existing root.key, if any, is replaced.
func Restore(dir string, backup []byte, passphrase []byte, opts Options) error {
	sealed, err := trust.UnmarshalSealedRootKey(backup)
	if err != nil {
		return err
	}
	if _, err := readDocument(filepath.Join(dir, documentFile), sealed.RootPublicKey()); err != nil {
		if errors.Is(err, trust.ErrBadSignature) {
			return ErrBackupKeyMismatch
		}
		return err
	}
	rootPriv, err := sealed.Open(passphrase)
	if err != nil {
		return err
	}
	wipe(rootPriv)
	if err := securefile.Replace(filepath.Join(dir, rootKeyFile), backup); err != nil {
		return fmt.Errorf("write root key: %w", err)
	}
	return nil
}
