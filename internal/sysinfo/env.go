package sysinfo

import "strings"

// Environment detection (F-172, #322): container or virtual machine,
// device model and install kind. It reads only local files and the
// registry; like the rest of the report it goes only to admin devices
// through the tunnel and into the owner's local diagnostics bundle.

// virtFromModel recognises common hypervisors from the firmware's vendor
// and product names.
func virtFromModel(vendor, product string) string {
	s := strings.ToLower(vendor + " " + product)
	switch {
	case strings.Contains(s, "vmware"):
		return "vmware"
	case strings.Contains(s, "virtualbox"), strings.Contains(s, "innotek"):
		return "virtualbox"
	case strings.Contains(s, "qemu"), strings.Contains(s, "kvm"):
		return "kvm"
	case strings.Contains(s, "microsoft corporation") && strings.Contains(s, "virtual"):
		return "hyperv"
	case strings.Contains(s, "xen"):
		return "xen"
	case strings.Contains(s, "parallels"):
		return "parallels"
	case strings.Contains(s, "amazon ec2"):
		return "aws"
	case strings.Contains(s, "google compute engine"):
		return "gce"
	case strings.Contains(s, "bochs"):
		return "bochs"
	}
	return ""
}

// joinModel builds "vendor product" without repeating the vendor and
// without firmware placeholders.
func joinModel(vendor, product string) string {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		switch strings.ToLower(s) {
		case "", "to be filled by o.e.m.", "system product name", "system manufacturer", "default string", "not applicable", "none":
			return ""
		}
		return s
	}
	vendor, product = clean(vendor), clean(product)
	if vendor == "" || strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
		return product
	}
	if product == "" {
		return vendor
	}
	return vendor + " " + product
}
