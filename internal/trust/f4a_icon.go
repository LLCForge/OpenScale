package trust

import (
	"fmt"
	"slices"
)

// Device icons (#233, ADR-0232). The owner picks a device type from a
// fixed set; the panel and the tray draw it next to the name. The icon is
// signed like every other device field, so no device or coordinator can
// relabel a camera as a laptop.

// DeviceIcon is a device type from a fixed set.
type DeviceIcon string

// Device icons.
const (
	IconLaptop  DeviceIcon = "laptop"
	IconDesktop DeviceIcon = "desktop"
	IconPhone   DeviceIcon = "phone"
	IconTablet  DeviceIcon = "tablet"
	IconServer  DeviceIcon = "server"
	IconNAS     DeviceIcon = "nas"
	IconPrinter DeviceIcon = "printer"
	IconCamera  DeviceIcon = "camera"
	IconTV      DeviceIcon = "tv"
	IconRouter  DeviceIcon = "router"
	IconOther   DeviceIcon = "other"
)

// DeviceIcons returns every icon in display order.
func DeviceIcons() []DeviceIcon {
	return []DeviceIcon{IconLaptop, IconDesktop, IconPhone, IconTablet, IconServer, IconNAS, IconPrinter, IconCamera, IconTV, IconRouter, IconOther}
}

// Valid reports whether i is one of DeviceIcons. The empty icon is not
// valid here; it means "no icon" and is omitted from the document.
func (i DeviceIcon) Valid() bool { return slices.Contains(DeviceIcons(), i) }

// SetDeviceIcon sets the named device's icon; "" removes it.
func (doc *Document) SetDeviceIcon(name string, icon DeviceIcon) error {
	if icon != "" && !icon.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownIcon, icon)
	}
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
		if idx < 0 {
			return ErrUnknownDevice
		}
		doc.Devices[idx].Icon = icon
		return nil
	})
}

func (doc *Document) validateIcons() error {
	for _, d := range doc.Devices {
		if d.Icon != "" && !d.Icon.Valid() {
			return fmt.Errorf("device %s: %w: %q", d.Name, ErrUnknownIcon, d.Icon)
		}
	}
	return nil
}
