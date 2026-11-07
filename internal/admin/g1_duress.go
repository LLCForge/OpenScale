package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Duress passphrase (#592, ADR-0176), owner side. The owner may set a
// second passphrase. When it is typed where the root passphrase is asked
// (panel sign-in), CheckLogin reports it; the caller then runs
// TriggerDuress, which overwrites and removes the local root key and the
// listed administrator key files, queues a silent alarm event and tells
// the caller to show a harmless, read-only decoy view. The real network is
// untouched: the owner restores the root key from a backup later, which is
// why a duress passphrase can only be set while a backup is recorded.
//
// Limits (stated in the ADR): overwriting a file does not guarantee the old
// blocks are gone on SSDs or copy-on-write file systems; a forensic look at
// the folder shows duress.json exists.

const (
	duressFile     = "duress.json"
	duressFormat   = "openscale-duress-v1"
	alarmOutbox    = "alarm-outbox.json"
	maxDuressFile  = 4096
	maxAlarmOutbox = 64 << 10
	maxAlarms      = 64
)

// Duress errors.
var (
	ErrDuressNoBackup = errors.New("a duress passphrase needs a recorded root key backup first")
	ErrDuressSame     = errors.New("the duress passphrase must differ from the root passphrase")
)

type duressRecord struct {
	Format string             `json:"format"`
	KDF    trust.Argon2Params `json:"kdf"`
	Salt   []byte             `json:"salt"`
	Hash   []byte             `json:"hash"`
}

// AlarmEvent is the silent alarm a duress sign-in raises. It carries no
// secret; the sender (G2: coordinator relay to the other admin devices,
// G4: tray) signs it with the device key.
type AlarmEvent struct {
	Kind      string    `json:"kind"`
	NetworkID string    `json:"network_id"`
	At        time.Time `json:"at"`
}

// AlarmSink delivers a silent alarm without showing anything on screen.
type AlarmSink interface {
	SendSilentAlarm(ctx context.Context, ev AlarmEvent) error
}

// DuressResult tells the caller what happened.
type DuressResult struct {
	// FakeReadOnly: show DuressDecoy read-only, never the real panel.
	FakeReadOnly bool     `json:"fake_read_only"`
	Wiped        []string `json:"wiped"`
	AlarmSent    bool     `json:"alarm_sent"`
	AlarmQueued  bool     `json:"alarm_queued"`
}

// SetDuressPassphrase stores a verifier for the duress passphrase. The
// root passphrase proves the owner; a backup must exist.
func (n *Network) SetDuressPassphrase(rootPass, duressPass []byte) error {
	if subtle.ConstantTimeCompare(rootPass, duressPass) == 1 {
		return ErrDuressSame
	}
	if err := trust.CheckPassphrase(duressPass); err != nil {
		return err
	}
	if err := n.CheckPassphrase(rootPass); err != nil {
		return err
	}
	backups, err := n.Backups()
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		return ErrDuressNoBackup
	}
	rec := duressRecord{Format: duressFormat, KDF: n.argon, Salt: make([]byte, 16)}
	if _, err := io.ReadFull(n.randomReader(), rec.Salt); err != nil {
		return fmt.Errorf("read salt: %w", err)
	}
	rec.Hash = argon2.IDKey(duressPass, rec.Salt, rec.KDF.Time, rec.KDF.MemoryKiB, rec.KDF.Threads, 32)
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(n.dir, duressFile), append(data, '\n'))
}

// ClearDuressPassphrase removes the duress verifier (root passphrase
// required).
func (n *Network) ClearDuressPassphrase(rootPass []byte) error {
	if err := n.CheckPassphrase(rootPass); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(n.dir, duressFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (n *Network) randomReader() io.Reader {
	if n.random != nil {
		return n.random
	}
	return rand.Reader
}

// DuressConfigured reports whether dir has a duress passphrase.
func DuressConfigured(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, duressFile))
	return err == nil
}

// IsDuressPassphrase reports whether pass is the duress passphrase of dir.
// It always runs the KDF when a verifier exists, so timing does not tell
// whether the typed passphrase matched.
func IsDuressPassphrase(dir string, pass []byte) bool {
	data, err := securefile.ReadPrivate(filepath.Join(dir, duressFile), maxDuressFile)
	if err != nil {
		return false
	}
	var rec duressRecord
	if json.Unmarshal(data, &rec) != nil || rec.Format != duressFormat || len(rec.Salt) != 16 || len(rec.Hash) != 32 {
		return false
	}
	if rec.KDF.Time < 1 || rec.KDF.Time > 10 || rec.KDF.MemoryKiB < 64*1024 || rec.KDF.MemoryKiB > 1024*1024 || rec.KDF.Threads < 1 || rec.KDF.Threads > 16 {
		return false
	}
	got := argon2.IDKey(pass, rec.Salt, rec.KDF.Time, rec.KDF.MemoryKiB, rec.KDF.Threads, 32)
	defer wipe(got)
	return subtle.ConstantTimeCompare(got, rec.Hash) == 1
}

// LoginKind is the result of CheckLogin.
type LoginKind int

// Login results.
const (
	LoginWrong LoginKind = iota
	LoginRoot
	LoginDuress
)

// CheckLogin classifies a sign-in passphrase: duress, root or wrong. The
// duress check runs first and both checks always run, so the time taken
// does not reveal the outcome.
func (n *Network) CheckLogin(pass []byte) LoginKind {
	duress := IsDuressPassphrase(n.dir, pass)
	rootErr := n.CheckPassphrase(pass)
	switch {
	case duress:
		return LoginDuress
	case rootErr == nil:
		return LoginRoot
	}
	return LoginWrong
}

// TriggerDuress overwrites and removes the root key in dir and the given
// administrator key files, then sends (or queues) the silent alarm.
// Errors wiping one file do not stop the others; the alarm always goes.
func TriggerDuress(ctx context.Context, dir string, adminKeyFiles []string, sink AlarmSink, networkID string, now time.Time) DuressResult {
	res := DuressResult{FakeReadOnly: true}
	for _, p := range append([]string{filepath.Join(dir, rootKeyFile)}, adminKeyFiles...) {
		if err := secureDelete(p); err == nil {
			res.Wiped = append(res.Wiped, p)
		}
	}
	ev := AlarmEvent{Kind: "duress", NetworkID: networkID, At: now.UTC().Truncate(time.Second)}
	if sink != nil {
		if err := sink.SendSilentAlarm(ctx, ev); err == nil {
			res.AlarmSent = true
			return res
		}
	}
	res.AlarmQueued = queueAlarm(dir, ev) == nil
	return res
}

// secureDelete overwrites a file with random bytes, syncs it, renames it
// to a random name and removes it (best effort against recovery).
func secureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	left := info.Size()
	for left > 0 {
		n := int64(len(buf))
		if left < n {
			n = left
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			f.Close()
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			f.Close()
			return err
		}
		left -= n
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(filepath.Dir(path), "."+hex.EncodeToString(rnd[:]))
	if os.Rename(path, tmp) == nil {
		path = tmp
	}
	return os.Remove(path)
}

func queueAlarm(dir string, ev AlarmEvent) error {
	path := filepath.Join(dir, alarmOutbox)
	var list []AlarmEvent
	if data, err := securefile.ReadPrivate(path, maxAlarmOutbox); err == nil {
		_ = json.Unmarshal(data, &list)
	}
	list = append(list, ev)
	if len(list) > maxAlarms {
		list = list[len(list)-maxAlarms:]
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// PendingAlarms returns and clears the queued silent alarms (G2/G4 send
// them when the network is reachable).
func PendingAlarms(dir string) ([]AlarmEvent, error) {
	path := filepath.Join(dir, alarmOutbox)
	data, err := securefile.ReadPrivate(path, maxAlarmOutbox)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []AlarmEvent
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, errors.New("alarm outbox is corrupt")
	}
	return list, os.Remove(path)
}

// DuressDecoy returns the harmless view shown after a duress sign-in: the
// network's name and domain and this device only, no rules, invites,
// groups, DNS records or other devices.
func DuressDecoy(doc *trust.Document, ownDevice string) *trust.Document {
	decoy := &trust.Document{NetworkID: doc.NetworkID, Version: doc.Version, IssuedAt: doc.IssuedAt, ExpiresAt: doc.ExpiresAt,
		DNSDomain: doc.DNSDomain, IPv4Prefix: doc.IPv4Prefix, IPv6Prefix: doc.IPv6Prefix, DisplayName: doc.DisplayName,
		Devices: []trust.Device{}, Revoked: []trust.Revocation{}, Rules: []trust.Rule{}}
	if d, ok := doc.DeviceByName(ownDevice); ok {
		d.Roles, d.Routes, d.Tags = []trust.Role{}, nil, nil
		decoy.Devices = append(decoy.Devices, d)
	}
	return decoy
}
