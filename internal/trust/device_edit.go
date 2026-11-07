package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Device membership and naming edits (ADR-0019).

// Errors of device edits.
var (
	ErrNameReserved    = errors.New("device name is reserved")
	ErrInvalidName     = errors.New("device name must be a lowercase DNS label (a-z, 0-9, -)")
	ErrSameName        = errors.New("the new name is the same as the current one")
	ErrInvalidLifetime = errors.New("device lifetime must be between 1 second and 3650 days")
)

// RenameDevice changes a device's name and rewrites every reference to the
// old name in rules, groups and exit_users in the same version. The
// device's id, keys and addresses stay; its MagicDNS name follows the new
// name.
func (doc *Document) RenameDevice(oldName, newName string) error {
	switch {
	case !isValidLabel(newName):
		return ErrInvalidName
	case newName == CoordinatorName:
		return ErrNameReserved
	case oldName == newName:
		return ErrSameName
	}
	if _, ok := doc.DeviceByName(oldName); !ok {
		return ErrUnknownDevice
	}
	if _, taken := doc.DeviceByName(newName); taken {
		return ErrNameTaken
	}
	rename := func(entries []string) {
		for i, e := range entries {
			if e == oldName {
				entries[i] = newName
			}
		}
	}
	return doc.transact(func() error {
		for i := range doc.Devices {
			if doc.Devices[i].Name == oldName {
				doc.Devices[i].Name = newName
			}
		}
		for i := range doc.Rules {
			rename(doc.Rules[i].From)
			rename(doc.Rules[i].To)
			rename(doc.Rules[i].Via)
		}
		for i := range doc.Groups {
			rename(doc.Groups[i].Members)
		}
		if doc.ExitUsers != nil {
			rename(*doc.ExitUsers)
		}
		doc.renameDNSRefs(oldName, newName)
		// DNS filter profiles (#416).
		doc.renameDNSProfileRefs(oldName, newName)
		doc.renamePolicyTests(oldName, newName) // ADR-0120
		doc.renameInternalCA(oldName, newName)  // ADR-0138
		return nil
	})
}

// ExtendDevice sets the named device's membership to end lifetime after
// now. It extends or shortens the membership; the lifetime is capped at
// MaxDeviceLife.
func (doc *Document) ExtendDevice(name string, now time.Time, lifetime time.Duration) (Device, error) {
	if lifetime < time.Second || lifetime > MaxDeviceLife {
		return Device{}, ErrInvalidLifetime
	}
	now = now.UTC().Truncate(time.Second)
	return doc.setDeviceExpiry(name, func(d Device) (time.Time, error) {
		end := now.Add(lifetime)
		if !end.After(d.AddedAt) {
			return time.Time{}, errors.New("the new end of membership is before the device was added; check the clock")
		}
		return end, nil
	})
}

// ExpireDevice ends the named device's membership now. Unlike RevokeDevice
// the device stays listed with its keys and can be extended again later.
func (doc *Document) ExpireDevice(name string, now time.Time) (Device, error) {
	now = now.UTC().Truncate(time.Second)
	return doc.setDeviceExpiry(name, func(d Device) (time.Time, error) {
		// expires_at must stay after added_at (Validate).
		if earliest := d.AddedAt.Add(time.Second); now.Before(earliest) {
			return earliest, nil
		}
		return now, nil
	})
}

func (doc *Document) setDeviceExpiry(name string, end func(Device) (time.Time, error)) (Device, error) {
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
	if idx < 0 {
		return Device{}, ErrUnknownDevice
	}
	at, err := end(doc.Devices[idx])
	if err != nil {
		return Device{}, err
	}
	prev := doc.Devices[idx].ExpiresAt
	doc.Devices[idx].ExpiresAt = at
	if err := doc.Validate(); err != nil {
		doc.Devices[idx].ExpiresAt = prev
		return Device{}, err
	}
	return doc.Devices[idx], nil
}

// transact runs mutate on doc and validates the result. If either fails,
// doc is restored to its previous state, so a failed edit never leaves a
// half-changed document behind.
func (doc *Document) transact(mutate func() error) error {
	backup, err := doc.clone()
	if err != nil {
		return err
	}
	if err := mutate(); err != nil {
		*doc = *backup
		return err
	}
	// An edit that adds an ADR-0232 field raises the client minimum with
	// it, so no edit produces a document older clients half-understand.
	RaiseMinClientForSchema(doc)
	if err := doc.Validate(); err != nil {
		*doc = *backup
		return err
	}
	return nil
}

// clone returns a deep copy through the document's own JSON encoding.
func (doc *Document) clone() (*Document, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}
	var out Document
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}
	normalizeSlices(&out)
	return &out, nil
}
