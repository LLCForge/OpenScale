//go:build !linux && !windows

package privacy

// hostnameExposure has no checks on this platform yet.
func hostnameExposure() []Finding {
	return []Finding{{SeverityInfo, "hostname_unknown", "bu platformda mDNS/DHCP ad duyurusu denetlenmiyor"}}
}

// crashDumpEnvironment has no checks on this platform yet.
func crashDumpEnvironment() []Finding { return nil }
