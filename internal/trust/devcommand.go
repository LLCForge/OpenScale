package trust

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Remote lock and wipe (#244, ADR-0128). The owner signs a command for one
// device with the root key; the coordinator only carries it. The device
// checks it against its pinned root and epoch, refuses replays and runs it
// only if its local setting allows remote commands. Revocation in the
// document stays the way to cut a device off the network; a command is
// for the moment before that, while the lost device is still a member.

// DeviceCommandContext is the signature context of device commands.
const DeviceCommandContext = "openscale/device-command/v1"

// Device command actions.
const (
	CommandLock = "lock" // lock the interactive session(s)
	CommandWipe = "wipe" // delete OpenScale's keys and state on the device
)

// Device command limits.
const (
	// MaxCommandValidity bounds how long a command may stay valid.
	MaxCommandValidity = 7 * 24 * time.Hour
	// MaxCommandLog bounds the nonces a device remembers.
	MaxCommandLog  = 256
	commandPrefix  = "oscmd1."
	maxCommandText = 4096
)

// Device command errors.
var (
	ErrCommandReplayed = errors.New("device command was already used")
	ErrCommandTarget   = errors.New("device command is for another device or network")
	ErrCommandExpired  = errors.New("device command has expired")
)

// DeviceCommand is the signed payload of a remote lock or wipe.
type DeviceCommand struct {
	NetworkID string    `json:"network_id"`
	DeviceID  string    `json:"device_id"`
	Action    string    `json:"action"`
	Nonce     string    `json:"nonce"`
	RootEpoch uint64    `json:"root_epoch,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewDeviceCommand returns a command with a fresh nonce.
func NewDeviceCommand(networkID, deviceID, action string, epoch uint64, now time.Time, validity time.Duration, random io.Reader) (DeviceCommand, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return DeviceCommand{}, fmt.Errorf("read nonce: %w", err)
	}
	c := DeviceCommand{
		NetworkID: networkID,
		DeviceID:  deviceID,
		Action:    action,
		Nonce:     hex.EncodeToString(nonce),
		RootEpoch: epoch,
		IssuedAt:  now.UTC().Truncate(time.Second),
		ExpiresAt: now.UTC().Truncate(time.Second).Add(validity),
	}
	return c, c.check()
}

func (c DeviceCommand) check() error {
	switch {
	case !isValidID(c.NetworkID):
		return errors.New("network_id must be 32 lowercase hex characters")
	case !isValidID(c.DeviceID):
		return errors.New("device_id must be 32 lowercase hex characters")
	case c.Action != CommandLock && c.Action != CommandWipe:
		return fmt.Errorf("unknown device command %q", c.Action)
	case !isValidID(c.Nonce):
		return errors.New("nonce must be 32 lowercase hex characters")
	case c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt):
		return errors.New("expires_at must be after issued_at")
	case c.ExpiresAt.Sub(c.IssuedAt) > MaxCommandValidity:
		return errors.New("device command validity is too long")
	}
	return nil
}

// SignDeviceCommand signs c with the root key.
func SignDeviceCommand(root ed25519.PrivateKey, c DeviceCommand) (Envelope, error) {
	payload, err := deviceCommandPayload(c)
	if err != nil {
		return Envelope{}, err
	}
	return Sign(root, DeviceCommandContext, payload)
}

// SignDeviceCommandWith signs c with a hardware-held root key (ADR-0123).
func SignDeviceCommandWith(signer DigestSigner, c DeviceCommand) (Envelope, error) {
	payload, err := deviceCommandPayload(c)
	if err != nil {
		return Envelope{}, err
	}
	return SignWithDigest(signer, DeviceCommandContext, payload)
}

func deviceCommandPayload(c DeviceCommand) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// OpenDeviceCommand verifies env against the member's current root and
// epoch and checks that it targets deviceID and is valid at now. It does not
// record the nonce; CommandLog.Use does.
func OpenDeviceCommand(env Envelope, s *State, deviceID string, now time.Time) (*DeviceCommand, error) {
	if len(env.Cosignatures) != 0 {
		return nil, errors.New("device commands carry no approvals")
	}
	payload, err := env.verifyRootSignature(s.Anchor.RootKey, DeviceCommandContext)
	if err != nil {
		return nil, err
	}
	var c DeviceCommand
	if err := decodeStrict(payload, &c); err != nil {
		return nil, fmt.Errorf("decode device command: %w", err)
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(c.NetworkID), []byte(s.Anchor.NetworkID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(c.DeviceID), []byte(deviceID)) != 1 {
		return nil, ErrCommandTarget
	}
	// A command signed before a root change is void: the old root may be
	// the compromised one (ADR-0027).
	if c.RootEpoch != s.Epoch {
		return nil, ErrEpochMismatch
	}
	if now.Before(c.IssuedAt.Add(-clockSkew)) {
		return nil, ErrNotYetValid
	}
	if !now.Before(c.ExpiresAt) {
		return nil, ErrCommandExpired
	}
	return &c, nil
}

// CommandLog remembers the nonces of commands a device has run until they
// expire, so a carried command runs at most once.
type CommandLog struct {
	Entries []CommandLogEntry `json:"entries"`
}

// CommandLogEntry is one used nonce.
type CommandLogEntry struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Use records c's nonce or returns ErrCommandReplayed. Expired entries are
// dropped first; a full log refuses new commands rather than forgetting a
// nonce that is still valid (fail closed).
func (l *CommandLog) Use(c *DeviceCommand, now time.Time) error {
	l.Entries = slices.DeleteFunc(l.Entries, func(e CommandLogEntry) bool { return !now.Before(e.ExpiresAt) })
	for _, e := range l.Entries {
		if e.Nonce == c.Nonce {
			return ErrCommandReplayed
		}
	}
	if len(l.Entries) >= MaxCommandLog {
		return errors.New("device command log is full")
	}
	l.Entries = append(l.Entries, CommandLogEntry{Nonce: c.Nonce, ExpiresAt: c.ExpiresAt})
	return nil
}

// EncodeDeviceCommand returns the single-line text form "oscmd1.<base64url>".
func EncodeDeviceCommand(env Envelope) (string, error) {
	if env.Context != DeviceCommandContext {
		return "", ErrWrongContext
	}
	data, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("encode device command: %w", err)
	}
	line := commandPrefix + base64.RawURLEncoding.EncodeToString(data)
	if len(line) > maxCommandText {
		return "", errors.New("device command is too large")
	}
	return line, nil
}

// DecodeDeviceCommand parses the text form. The result is untrusted until
// OpenDeviceCommand succeeds.
func DecodeDeviceCommand(line string) (Envelope, error) {
	line = strings.TrimSpace(line)
	if len(line) > maxCommandText || !strings.HasPrefix(line, commandPrefix) {
		return Envelope{}, errors.New("not a device command")
	}
	data, err := base64.RawURLEncoding.DecodeString(line[len(commandPrefix):])
	if err != nil {
		return Envelope{}, errors.New("not a device command")
	}
	env, err := UnmarshalEnvelope(data)
	if err != nil {
		return Envelope{}, err
	}
	if env.Context != DeviceCommandContext {
		return Envelope{}, ErrWrongContext
	}
	return env, nil
}
