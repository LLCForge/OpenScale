package osnet

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// WSL2 compatibility (#490). Windows Subsystem for Linux 2 runs the
// distribution in a light virtual machine. In the default NAT mode its
// traffic leaves through the Windows host, so the Windows tunnel already
// carries it, but the distribution's interface keeps MTU 1500 while the
// tunnel uses wslTunnelMTU (node.DefaultMTU); in the mirrored mode the distribution sees
// the Windows interfaces, routes included. OpenScale does not change WSL
// settings; it reads them and explains what to do.

// WSL networking modes from .wslconfig ([wsl2] networkingMode).
const (
	WSLModeNAT       = "nat"
	WSLModeMirrored  = "mirrored"
	WSLModeBridged   = "bridged"
	WSLModeNone      = "none"
	WSLModeVirtio    = "virtioproxy"
	maxWSLConfigSize = 64 << 10
	// wslTunnelMTU is node.DefaultMTU (osnet cannot import node).
	wslTunnelMTU = 1280
)

// WSLInfo describes WSL on this computer or inside this distribution.
type WSLInfo struct {
	// Inside is true when this program runs inside a WSL distribution.
	Inside bool `json:"inside,omitempty"`
	// Version is 1 or 2 inside WSL; 0 when unknown or outside.
	Version int `json:"version,omitempty"`
	// Installed is true on Windows when wsl.exe exists.
	Installed bool `json:"installed,omitempty"`
	// ConfigRead is true when a .wslconfig was found and read.
	ConfigRead bool `json:"config_read,omitempty"`
	// Mode is the networking mode; "nat" when the file does not set one.
	Mode string `json:"mode,omitempty"`
	// DNSTunneling is the dnsTunneling setting when the file sets it.
	DNSTunneling *bool `json:"dns_tunneling,omitempty"`
	// Notes are Turkish instructions for the owner.
	Notes []string `json:"notes,omitempty"`
}

// ParseWSLConfig reads the [wsl2] section of a .wslconfig file. Unknown
// modes are kept as "" (treated like the default).
func ParseWSLConfig(data []byte) (mode string, dnsTunneling *bool) {
	if len(data) > maxWSLConfigSize {
		data = data[:maxWSLConfigSize]
	}
	mode = WSLModeNAT
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section != "wsl2" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if i := strings.IndexAny(v, "#;"); i >= 0 {
			v = v[:i]
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
		switch k {
		case "networkingmode":
			switch v {
			case WSLModeNAT, WSLModeMirrored, WSLModeBridged, WSLModeNone, WSLModeVirtio:
				mode = v
			default:
				mode = ""
			}
		case "dnstunneling":
			if v == "true" || v == "false" {
				b := v == "true"
				dnsTunneling = &b
			}
		}
	}
	return mode, dnsTunneling
}

// ParseWSLKernel reads the kernel release (/proc/sys/kernel/osrelease)
// and reports whether it is a WSL kernel and which version.
func ParseWSLKernel(release string) (inside bool, version int) {
	r := strings.ToLower(release)
	if !strings.Contains(r, "microsoft") {
		return false, 0
	}
	// WSL2 kernels are "...-microsoft-standard-WSL2"; WSL1 reports the
	// Windows build with "-Microsoft".
	if strings.Contains(r, "wsl2") || strings.Contains(r, "microsoft-standard") {
		return true, 2
	}
	return true, 1
}

// WSLNotes explains, in Turkish, how to use the tunnel with WSL.
func WSLNotes(w WSLInfo) []string {
	mtu := strconv.Itoa(wslTunnelMTU)
	var out []string
	if w.Inside {
		if w.Version == 1 {
			out = append(out, "Bu dağıtım WSL1'de çalışıyor: ağ Windows ile ortaktır, Windows'taki OpenScale tüneli doğrudan kullanılır; WSL içinde ayrı OpenScale çalıştırmayın.")
			return out
		}
		out = append(out,
			"Bu Linux WSL2 içinde çalışıyor. Önerilen yol Windows'taki OpenScale tünelini kullanmaktır; WSL içinde ayrı bir düğüm çalıştıracaksanız onu ayrı bir cihaz olarak ağa katın (systemd açık olmalı: /etc/wsl.conf içinde [boot] systemd=true).",
			"NAT kipinde WSL arayüzü 1500 MTU ile kalır; tünel "+mtu+" kullandığı için büyük paketler takılabilir: sudo ip link set dev eth0 mtu "+mtu,
			"Yansıtılmış kipte (networkingMode=mirrored) Windows'taki OpenScale arayüzü ve rotaları WSL içinde de görünür; WSL içinde ikinci bir tünel açmayın.")
		return out
	}
	if !w.Installed {
		return nil
	}
	if w.Mode == "" && !w.ConfigRead {
		return append(out, "WSL kurulu. Ağ kipi kullanıcının .wslconfig dosyasındadır; kendi hesabınızda 'openscale platform wsl' ile ayrıntılı öneri alın.")
	}
	switch w.Mode {
	case WSLModeMirrored:
		out = append(out, "WSL2 yansıtılmış kipte: dağıtımlar OpenScale arayüzünü ve rotalarını Windows ile ortak görür; ek ayar gerekmez.")
		if w.DNSTunneling == nil || !*w.DNSTunneling {
			out = append(out, "OpenScale adlarının (MagicDNS) WSL içinde çözülmesi için .wslconfig dosyasında [wsl2] altına dnsTunneling=true ekleyin ve 'wsl --shutdown' çalıştırın.")
		}
	case WSLModeNAT, "":
		out = append(out,
			"WSL2 NAT kipinde: dağıtımın trafiği Windows üzerinden çıkar, OpenScale adreslerine ek rota gerekmez.",
			"WSL içinde MTU'yu tünelle eşitleyin, yoksa büyük paketler takılabilir: sudo ip link set dev eth0 mtu "+mtu,
			"Daha az sorun için yansıtılmış kip önerilir: .wslconfig dosyasında [wsl2] altına networkingMode=mirrored ve dnsTunneling=true yazıp 'wsl --shutdown' çalıştırın.")
	case WSLModeBridged, WSLModeNone, WSLModeVirtio:
		out = append(out, "WSL2 ağ kipi '"+w.Mode+"': bu kipte Windows'taki tünel dağıtıma otomatik geçmeyebilir; WSL içinde ayrı bir OpenScale cihazı çalıştırın veya kipi 'mirrored' yapın.")
	}
	out = append(out, "Kill switch açıkken WSL trafiğinin davranışı gerçek bir WSL kurulumunda henüz denenmedi; çıkış düğümü kullanırken WSL içinden bir sitenin açılıp açılmadığını ve hangi adresten çıkıldığını denetleyin.")
	return out
}
