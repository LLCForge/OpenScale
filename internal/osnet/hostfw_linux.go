//go:build linux

package osnet

import (
	"context"
	"fmt"
	"strings"
)

// CheckHostFirewall looks for firewalld, ufw and nftables input policies
// that would drop traffic on iface (#283). In "auto" mode a firewalld zone
// is changed for this run only (runtime, not --permanent); nothing else is
// ever changed.
func CheckHostFirewall(ctx context.Context, iface, mode string) ([]HostFirewallFinding, error) {
	return checkHostFirewall(ctx, hostOps, iface, mode)
}

func checkHostFirewall(ctx context.Context, o sysOps, iface, mode string) ([]HostFirewallFinding, error) {
	if err := ValidHostFirewallMode(mode); err != nil {
		return nil, err
	}
	if mode == HostFirewallOff {
		return nil, nil
	}
	if !validNftIfname(iface) {
		return nil, fmt.Errorf("geçersiz arayüz adı %q", iface)
	}
	var out []HostFirewallFinding
	managed := false
	if o.has("firewall-cmd") {
		if state, err := o.run(ctx, nil, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(state)) == "running" {
			managed = true
			zone, err := o.run(ctx, nil, "firewall-cmd", "--get-zone-of-interface="+iface)
			z := strings.TrimSpace(string(zone))
			if err != nil || z != "trusted" {
				fix := "firewall-cmd --zone=trusted --change-interface=" + iface
				f := HostFirewallFinding{Tool: "firewalld", Fix: "sudo " + fix,
					Message: "firewalld çalışıyor ve tünel arayüzü güvenilir bölgede değil; eşlerden gelen bağlantılar engellenebilir"}
				if mode == HostFirewallAuto {
					if _, err := o.run(ctx, nil, "firewall-cmd", "--zone=trusted", "--change-interface="+iface); err == nil {
						f.Fixed, f.Fix = true, ""
						f.Message = "firewalld: tünel arayüzü bu çalışma için 'trusted' bölgesine alındı (kalıcı değil; erişim kurallarını OpenScale uygular)"
					}
				}
				out = append(out, f)
			}
		}
	}
	if o.has("ufw") {
		if status, err := o.run(ctx, nil, "ufw", "status", "verbose"); err == nil {
			if strings.Contains(string(status), "Status: active") {
				managed = true
			}
			if ufwBlocks(string(status), iface) {
				out = append(out, HostFirewallFinding{Tool: "ufw", Fix: "sudo ufw allow in on " + iface,
					Message: "ufw gelen trafiği varsayılan olarak engelliyor ve tünel arayüzü için kural yok; ufw kalıcı yapılandırmasına OpenScale dokunmaz"})
			}
		}
	}
	// Tailscale on the same host: its own chain, rebuilt whenever Tailscale
	// restarts, so OpenScale only reports it and never edits it.
	if o.has("iptables") {
		if rules, err := o.run(ctx, nil, "iptables", "-S", "ts-input"); err == nil && tailscaleDropsTunnel(string(rules), iface) {
			out = append(out, HostFirewallFinding{Tool: "tailscale",
				Fix: "sudo iptables -I ts-input 1 -i " + iface + " -j ACCEPT",
				Message: "Tailscale bu makinede " + tailscaleCGNAT + " aralığından gelen ve kendi arayüzüne ait olmayan trafiği düşürüyor; OpenScale adresleri bu aralıkta olduğu için eşlerden gelen bağlantılar ulaşmaz. " +
					"Önerilen komut Tailscale yeniden başlayınca silinir; kalıcı çözüm OpenScale ağını bu aralığın dışında kurmaktır"})
		}
	}
	if !managed && o.has("nft") {
		if rs, err := o.run(ctx, nil, "nft", "list", "ruleset"); err == nil {
			for _, c := range nftInputDrops(string(rs), iface) {
				parts := strings.Fields(c)
				out = append(out, HostFirewallFinding{Tool: "nftables",
					Fix:     fmt.Sprintf("sudo nft insert rule %s %s %s iifname %q accept", parts[0], parts[1], parts[2], iface),
					Message: fmt.Sprintf("nftables %s tablosunun %s zinciri gelen trafiği varsayılan olarak düşürüyor ve tünel arayüzünü anmıyor", parts[0]+" "+parts[1], parts[2])})
			}
		}
	}
	return out, nil
}
