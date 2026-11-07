//go:build !linux

package osnet

import "fmt"

// Netfilter backends for the exit node rules (Linux only).
const (
	NetfilterAuto     = "auto"
	NetfilterNFTables = "nftables"
	NetfilterIPTables = "iptables"
)

// SetNetfilterMode only validates the mode here: exit node rules exist on
// Linux only.
func SetNetfilterMode(mode string) error {
	switch mode {
	case NetfilterAuto, NetfilterNFTables, NetfilterIPTables:
		return nil
	}
	return fmt.Errorf("geçersiz netfilter kipi %q (auto, nftables veya iptables)", mode)
}
