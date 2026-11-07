package admin

import (
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Apply prepares change on the current document and signs it in one step.
// It returns the committed plan so callers can show what was signed. Use
// Prepare and Commit separately to show the difference before asking for
// the passphrase.
func (n *Network) Apply(passphrase []byte, now time.Time, change Change) (*Plan, error) {
	plan, err := n.Prepare(now, trust.DefaultValidity, change)
	if err != nil {
		return nil, err
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return nil, err
	}
	return plan, nil
}

// ExtendDevice sets the device's membership to end lifetime after now, at
// most trust.MaxDeviceLife (ADR-0019, F-104).
func (n *Network) ExtendDevice(passphrase []byte, name string, lifetime time.Duration, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		_, err := doc.ExtendDevice(name, now, lifetime)
		return err
	})
}

// ExpireDevice ends the device's membership now without revoking its keys
// (ADR-0019).
func (n *Network) ExpireDevice(passphrase []byte, name string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		_, err := doc.ExpireDevice(name, now)
		return err
	})
}

// RenameDevice renames a device and every reference to it (ADR-0019,
// F-108). Its MagicDNS name changes with it.
func (n *Network) RenameDevice(passphrase []byte, oldName, newName string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.RenameDevice(oldName, newName)
	})
}

// SetDeviceTags replaces a device's tags (ADR-0021, F-072).
func (n *Network) SetDeviceTags(passphrase []byte, name string, tags []string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetDeviceTags(name, tags)
	})
}

// SetGroup creates or replaces a group (ADR-0021, F-072).
func (n *Network) SetGroup(passphrase []byte, name string, members []string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetGroup(name, members)
	})
}

// RemoveGroup deletes a group that no rule or exit_users refers to.
func (n *Network) RemoveGroup(passphrase []byte, name string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.RemoveGroup(name)
	})
}

// SetRuleDisabled turns a rule off or back on without deleting it
// (ADR-0021, F-078).
func (n *Network) SetRuleDisabled(passphrase []byte, index int, disabled bool, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetRuleDisabled(index, disabled)
	})
}

// SetExitUsers limits exit node use to the listed devices, tags and groups;
// an empty list allows no device (ADR-0021, F-036).
func (n *Network) SetExitUsers(passphrase []byte, users []string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetExitUsers(users)
	})
}

// ClearExitUsers lets every device use exit nodes again.
func (n *Network) ClearExitUsers(passphrase []byte, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.ClearExitUsers()
	})
}

// SetDNS replaces the network-wide DNS settings; nil removes them
// (ADR-0024, F-051, F-052).
func (n *Network) SetDNS(passphrase []byte, settings *trust.DNSSettings, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetDNS(settings)
	})
}

// SetDisplayName sets the network's display name shown in the tray and
// the panel; an empty name removes it (F-160).
func (n *Network) SetDisplayName(passphrase []byte, name string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetDisplayName(name)
	})
}
