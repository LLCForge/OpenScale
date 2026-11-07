//go:build windows

package privacy

import (
	"golang.org/x/sys/windows/registry"
)

// hostnameExposure reads (never changes) the Windows settings that
// announce the computer name on the local network (#40). Turning them off
// is a system-wide decision for the owner.
func hostnameExposure() []Finding {
	var out []Finding
	if v, ok := readDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, "EnableMDNS"); !ok || v != 0 {
		out = append(out, Finding{SeverityInfo, "mdns_on", "mDNS açık: bilgisayar adı yerel ağda duyurulur (Windows varsayılanı; kapatmak sistem ayarıdır)"})
	}
	if v, ok := readDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast"); !ok || v != 0 {
		out = append(out, Finding{SeverityInfo, "llmnr_on", "LLMNR açık: ad sorguları ve bilgisayar adı yerel ağa yayınlanır (grup ilkesiyle kapatılabilir)"})
	}
	out = append(out, Finding{SeverityInfo, "dhcp_hostname", "Windows DHCP isteklerinde bilgisayar adını gönderir; yerel ağın yöneticisi adı görür"})
	return out
}

// crashDumpEnvironment reports a machine-wide WER LocalDumps setting.
// OpenScale processes opt out per process, but other tools may still dump
// them (for example a debugger run by an administrator).
func crashDumpEnvironment() []Finding {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	k.Close()
	return []Finding{{SeverityInfo, "wer_localdumps", "Windows Hata Bildirimi yerel döküm (LocalDumps) bu bilgisayarda ayarlı; OpenScale kendi süreçlerinde WER'i kapatır"}}
}

func readDWORD(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}
