package autoupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

const (
	maxSmallFile   = 16 << 10
	settingsFormat = 1
	requestFormat  = "openscale-autoupdate-request-v1"
	resultFormat   = "openscale-autoupdate-result-v1"
	statusSchema   = 1
)

// Settings is the per-device switch. Automatic updates are on unless the
// owner turned them off (the owner's choice for this network, ADR-0225).
type Settings struct {
	Schema  int  `json:"schema"`
	Enabled bool `json:"enabled"`
}

// ReadSettings reads the switch; a missing file is on. A damaged file is an
// error and counts as off: nothing is installed on a setting nobody can read.
func ReadSettings(path string) (Settings, error) {
	data, err := securefile.ReadPrivate(path, maxSmallFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{Schema: settingsFormat, Enabled: true}, nil
	}
	if err != nil {
		return Settings{Schema: settingsFormat}, err
	}
	var s Settings
	if err := decodeStrict(data, &s); err != nil || s.Schema != settingsFormat {
		return Settings{Schema: settingsFormat}, fmt.Errorf("%s bozuk", path)
	}
	return s, nil
}

// WriteSettings saves the switch (administrator or root only).
func WriteSettings(path string, on bool) error {
	data, err := json.Marshal(Settings{Schema: settingsFormat, Enabled: on})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// States of Status.State.
const (
	StateOff         = "off"
	StateUnsupported = "unsupported"
	StateWaitingKey  = "waiting-key"
	StateNoRelease   = "no-release"
	StateUnreachable = "unreachable"
	StateUpToDate    = "up-to-date"
	StateRejected    = "rejected"
	StateScheduled   = "scheduled"
	StateDownloading = "downloading"
	StateInstalling  = "installing"
	StateFailed      = "failed"
	StatePending     = "pending"
)

// Attempt is the outcome of the last installation.
type Attempt struct {
	Version    string    `json:"version"`
	At         time.Time `json:"at"`
	OK         bool      `json:"ok"`
	RolledBack bool      `json:"rolledBack,omitempty"`
	Message    string    `json:"message,omitempty"`
}

// Status is what "update auto status" and the panel show.
type Status struct {
	Schema  int    `json:"schema"`
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	// Message explains the state (Turkish); Action is a command to run.
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Channel string `json:"channel"`
	Current string `json:"current"`
	// Latest is the version the coordinator announces; LatestVerified tells
	// whether its signed manifest verified on this device.
	Latest         string    `json:"latest,omitempty"`
	LatestVerified bool      `json:"latestVerified"`
	LastCheck      time.Time `json:"lastCheck,omitzero"`
	NextCheck      time.Time `json:"nextCheck,omitzero"`
	ScheduledAt    time.Time `json:"scheduledAt,omitzero"`
	LastAttempt    *Attempt  `json:"lastAttempt,omitempty"`
	// Source is the coordinator's upstream source ("github.com/owner/repo")
	// and SourceChecked its last check, as the coordinator reports them;
	// empty when the owner publishes by hand.
	Source        string    `json:"source,omitempty"`
	SourceChecked time.Time `json:"sourceChecked,omitzero"`
	// Ring is this device's update ring from its signed tags and Rollout
	// the coordinator's progress for the announced release (ADR-0235).
	Ring    string         `json:"ring,omitempty"`
	Rollout *RolloutStatus `json:"rollout,omitempty"`
}

// ReadStatus reads the status the device process saved in work.
func ReadStatus(work string) (Status, error) {
	data, err := securefile.ReadPrivate(filepath.Join(work, StatusFile), maxSmallFile)
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil || st.Schema != statusSchema {
		return Status{}, errors.New("otomatik güncelleme durumu okunamadı")
	}
	return st, nil
}

func writeStatus(work string, st Status) error {
	st.Schema = statusSchema
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(work, StatusFile), data)
}

// Request hands a downloaded and pre-checked release to the installer. The
// installer trusts none of it: it verifies the files in CacheDir again.
type Request struct {
	Format string `json:"format"`
	// Version and Digest (SHA-256 of the signed manifest) identify the
	// release; Mode is ModeBinary or ModeDeb.
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Mode    string `json:"mode"`
	// Manifest, Revocations and Payload are file names in CacheDir.
	Manifest    string `json:"manifest"`
	Revocations string `json:"revocations,omitempty"`
	Payload     string `json:"payload"`
	// Artifact is the payload's name in the manifest; Compressed tells that
	// Payload is gzip.
	Artifact   string    `json:"artifact"`
	Compressed bool      `json:"compressed,omitempty"`
	Created    time.Time `json:"created"`
}

// Result is what the installer reports back.
type Result struct {
	Format     string    `json:"format"`
	Version    string    `json:"version"`
	Digest     string    `json:"digest"`
	OK         bool      `json:"ok"`
	RolledBack bool      `json:"rolledBack,omitempty"`
	Message    string    `json:"message,omitempty"`
	At         time.Time `json:"at"`
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

func readResult(work string) (*Result, error) {
	data, err := securefile.ReadPrivate(filepath.Join(work, ResultFile), maxSmallFile)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := decodeStrict(data, &r); err != nil || r.Format != resultFormat {
		return nil, errors.New("kurulum sonucu bozuk")
	}
	return &r, nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
