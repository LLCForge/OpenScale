package posture

import (
	"fmt"
	"net"
	"strings"
)

// WiFiInterface is a wireless network interface and its current hardware
// address (#41).
type WiFiInterface struct {
	Name string
	MAC  net.HardwareAddr
}

// Randomized reports whether mac is a locally administered address. Wi-Fi
// MAC randomization (Windows "random hardware addresses", Android, iOS,
// NetworkManager "cloned-mac-address=random") always sets this bit; a
// burned-in vendor address never does.
func Randomized(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&0x02 != 0
}

// MACAdvice returns one Turkish warning per Wi-Fi interface that uses its
// burned-in hardware address. The address is visible to every Wi-Fi
// network the device joins; an exit node hides the traffic but not the
// MAC, so the owner is told to turn randomization on.
func MACAdvice(ifs []WiFiInterface) []string {
	var out []string
	for _, i := range ifs {
		if len(i.MAC) != 6 || Randomized(i.MAC) {
			continue
		}
		out = append(out, fmt.Sprintf("%s arayüzü üreticinin sabit MAC adresini kullanıyor; bağlandığınız Wi-Fi ağları cihazı tanıyabilir. İşletim sisteminin Wi-Fi ayarlarından rastgele donanım adresini açın (çıkış düğümü trafiği gizler, MAC adresini gizlemez).", i.Name))
	}
	return out
}

// WiFiInterfaces lists wireless interfaces that are up.
func WiFiInterfaces() []WiFiInterface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []WiFiInterface
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		if isWireless(i.Name) {
			out = append(out, WiFiInterface{Name: i.Name, MAC: i.HardwareAddr})
		}
	}
	return out
}

// wirelessByName is the name heuristic used where the system offers no
// cheap wireless flag (Windows friendly names, BSD driver names).
func wirelessByName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"wi-fi", "wifi", "wlan", "wireless", "kablosuz"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return strings.HasPrefix(n, "wl") || strings.HasPrefix(n, "ath") || strings.HasPrefix(n, "iwm") || strings.HasPrefix(n, "iwn")
}
