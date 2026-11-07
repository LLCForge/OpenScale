//go:build linux

package privacy

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// hostnameExposure reads (never changes) the usual Linux sources of host
// name announcements on the local network (#40).
func hostnameExposure() []Finding {
	var out []Finding
	if _, err := os.Stat("/run/avahi-daemon/pid"); err == nil {
		out = append(out, Finding{SeverityInfo, "mdns_on", "avahi-daemon çalışıyor: bilgisayar adı mDNS ile yerel ağda duyurulur"})
	}
	resolved := confValues([]string{"/etc/systemd/resolved.conf"}, "/etc/systemd/resolved.conf.d")
	if v, ok := resolved["llmnr"]; !ok || truthy(v) {
		if _, err := os.Stat("/run/systemd/resolve"); err == nil {
			out = append(out, Finding{SeverityInfo, "llmnr_on", "systemd-resolved LLMNR açık: bilgisayar adı yerel ağda yanıtlanır (LLMNR=no ile kapatılır)"})
		}
	}
	if v, ok := resolved["multicastdns"]; ok && truthy(v) {
		out = append(out, Finding{SeverityInfo, "resolved_mdns_on", "systemd-resolved mDNS açık: bilgisayar adı yerel ağda duyurulur"})
	}
	nm := confValues([]string{"/etc/NetworkManager/NetworkManager.conf"}, "/etc/NetworkManager/conf.d")
	if _, err := os.Stat("/run/NetworkManager"); err == nil {
		v4, ok4 := nm["ipv4.dhcp-send-hostname"]
		v6, ok6 := nm["ipv6.dhcp-send-hostname"]
		if !ok4 || truthy(v4) || !ok6 || truthy(v6) {
			out = append(out, Finding{SeverityInfo, "dhcp_hostname", "NetworkManager DHCP isteklerinde bilgisayar adını gönderebilir (dhcp-send-hostname=false ile kapatılır)"})
		}
	}
	return out
}

// crashDumpEnvironment reports where the kernel would send a core dump.
func crashDumpEnvironment() []Finding {
	b, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		return nil
	}
	p := strings.TrimSpace(string(b))
	if f := strings.Fields(strings.TrimPrefix(p, "|")); strings.HasPrefix(p, "|") && len(f) > 0 {
		return []Finding{{SeverityInfo, "core_pattern_pipe", "çekirdek dökümleri bir programa aktarılıyor (" + filepath.Base(f[0]) + "); OpenScale süreçleri kendilerini dökülemez işaretler"}}
	}
	return nil
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "no", "false", "0", "off":
		return false
	}
	return true
}

// confValues reads key=value lines (lower-case keys, last one wins) from
// INI-like files; sections are ignored, which is enough for these keys.
func confValues(files []string, dropIn string) map[string]string {
	if matches, err := filepath.Glob(filepath.Join(dropIn, "*.conf")); err == nil {
		files = append(files, matches...)
	}
	out := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil || len(data) > maxReadSize {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if ok {
				out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	return out
}
