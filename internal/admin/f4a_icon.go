package admin

import (
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// iconString renders a device icon in the change list; "-" when none.
func iconString(i trust.DeviceIcon) string {
	if i == "" {
		return "-"
	}
	return string(i)
}

// SetDeviceIcon sets or (with "") removes a device's icon (#233, ADR-0232).
// Prepare raises the minimum client version when the first icon appears.
func (n *Network) SetDeviceIcon(name string, icon trust.DeviceIcon, now time.Time, validity time.Duration) (*Plan, error) {
	return n.Prepare(now, validity, func(doc *trust.Document) error {
		return doc.SetDeviceIcon(name, icon)
	})
}
