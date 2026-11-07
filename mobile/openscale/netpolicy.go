package openscale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// Mobile data and Wi-Fi policies (#179, P27): the exit node to use is
// chosen by the network the phone is on. Rules are checked in order and
// the first match wins; with no match the manually chosen exit node
// stays. The app reports the network type (and, only when the owner gave
// location permission for SSID rules, the Wi-Fi name); the evaluation is
// here so it is tested. SSIDs are not authenticated: anyone can name a
// network "Home", so a rule that turns the exit node off for an SSID is
// warned about.

// Network kinds the app reports.
const (
	netWiFi     = "wifi"
	netCellular = "cellular"
	netEthernet = "ethernet"
	netAny      = "any"
)

// Policy limits.
const (
	maxPolicy      = 16 << 10
	maxPolicyRules = 32
	maxSSID        = 32 // bytes, IEEE 802.11
)

type networkPolicy struct {
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	// Network is wifi, cellular, ethernet or any.
	Network string `json:"network"`
	// SSID narrows a wifi rule to one network name ("" is any Wi-Fi).
	SSID string `json:"ssid,omitempty"`
	// NetID narrows a wifi or ethernet rule to one network recognized
	// without location permission (#477, NetworkID); "" is any.
	NetID string `json:"net_id,omitempty"`
	// ExitNode is the exit node on this network; "" means none.
	ExitNode string `json:"exit_node"`
}

func parsePolicy(s string) (networkPolicy, error) {
	var p networkPolicy
	if len(s) > maxPolicy {
		return p, errors.New("ağ politikası fazla büyük")
	}
	if strings.TrimSpace(s) == "" {
		return p, nil
	}
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("ağ politikası okunamadı: %w", err)
	}
	if len(p.Rules) > maxPolicyRules {
		return p, fmt.Errorf("en fazla %d kural olabilir", maxPolicyRules)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		r.ExitNode = strings.TrimSpace(r.ExitNode)
		switch r.Network {
		case netWiFi, netCellular, netEthernet, netAny:
		default:
			return p, fmt.Errorf("kural %d: bilinmeyen ağ türü %q", i+1, r.Network)
		}
		if r.SSID != "" && r.Network != netWiFi {
			return p, fmt.Errorf("kural %d: ağ adı yalnızca Wi-Fi kuralında verilir", i+1)
		}
		if r.NetID != "" && (r.Network != netWiFi && r.Network != netEthernet || !validNetID(r.NetID)) {
			return p, fmt.Errorf("kural %d: ağ kimliği yalnızca Wi-Fi veya kablolu kuralında ve n1- biçiminde verilir", i+1)
		}
		if len(r.SSID) > maxSSID {
			return p, fmt.Errorf("kural %d: ağ adı en fazla %d bayt", i+1, maxSSID)
		}
		if len(r.ExitNode) > 253 {
			return p, fmt.Errorf("kural %d: çıkış düğümü adı fazla uzun", i+1)
		}
	}
	return p, nil
}

func (r policyRule) matches(network, ssid, netID string) bool {
	if r.Network != netAny && r.Network != network {
		return false
	}
	// An unknown identity (no gateway or DNS yet) matches no identity rule.
	if r.NetID != "" && netID != r.NetID {
		return false
	}
	if r.SSID == "" {
		return true
	}
	// An unknown SSID (no permission, location off) matches no SSID rule.
	return ssid != "" && ssid == r.SSID
}

// normalizeSSID strips the quotes Android puts around a UTF-8 SSID and
// maps its "unknown" marker to "".
func normalizeSSID(s string) string {
	if s == "<unknown ssid>" {
		return ""
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ExitNodeForNetwork returns the exit node policy picks for the network
// the phone is on: network is wifi, cellular, ethernet (anything else is
// treated as matching only "any" rules) and ssid the Wi-Fi name, "" when
// unknown. fallback (the manual choice) is returned when no rule matches.
func ExitNodeForNetwork(policy, network, ssid, fallback string) (string, error) {
	return ExitNodeForNetworkID(policy, network, ssid, "", fallback)
}

// ExitNodeForNetworkID is ExitNodeForNetwork with the network identity
// the app computed with NetworkID (#477), "" when unknown.
func ExitNodeForNetworkID(policy, network, ssid, netID, fallback string) (string, error) {
	p, err := parsePolicy(policy)
	if err != nil {
		return "", err
	}
	ssid = normalizeSSID(ssid)
	if !validNetID(netID) {
		netID = ""
	}
	for _, r := range p.Rules {
		if r.matches(network, ssid, netID) {
			return r.ExitNode, nil
		}
	}
	return strings.TrimSpace(fallback), nil
}

// CheckNetworkPolicy validates a policy before the app saves it and
// returns warnings as a JSON array of strings. With a joined stateDir the
// exit node names are checked against the network document.
func CheckNetworkPolicy(stateDir, policy string) (string, error) {
	p, err := parsePolicy(policy)
	if err != nil {
		return "", err
	}
	var doc *trust.Document
	if checkStateDir(stateDir) == nil {
		if store, err := member.Open(stateDir); err == nil {
			doc = store.Document()
		}
	}
	warnings := []string{}
	catchAll := -1
	for i, r := range p.Rules {
		if catchAll >= 0 {
			warnings = append(warnings, fmt.Sprintf("kural %d hiç uygulanmaz: kural %d her ağı zaten kapsıyor", i+1, catchAll+1))
			continue
		}
		if r.Network == netAny {
			catchAll = i
		}
		if r.SSID != "" && r.ExitNode == "" {
			warnings = append(warnings, fmt.Sprintf("kural %d: Wi-Fi adı doğrulanmaz; aynı adlı sahte bir ağ çıkış düğümünü kapattırabilir", i+1))
		}
		if r.NetID != "" && r.ExitNode == "" {
			warnings = append(warnings, fmt.Sprintf("kural %d: ağ kimliği doğrulanmaz; aynı ağ geçidi ve DNS ayarlarını taşıyan başka bir ağ çıkış düğümünü kapattırabilir", i+1))
		}
		if r.ExitNode != "" && doc != nil {
			d, ok := doc.DeviceByName(r.ExitNode)
			if !ok || !d.HasRole(trust.RoleExitNode) {
				return "", fmt.Errorf("kural %d: %q ağda bir çıkış düğümü değil", i+1, r.ExitNode)
			}
		}
	}
	out, err := json.Marshal(warnings)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
