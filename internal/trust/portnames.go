package trust

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Well-known service names usable instead of port numbers when writing a
// rule (#110, ADR-0120). They are expanded when the rule is written, by the
// CLI, the panel and the policy file; the signed document always holds
// numbers, so devices need no name table and every version agrees on the
// meaning. They are different from OpenScale's own service rules
// (Rule.Service): "ssh" here is the operating system's SSH server on port
// 22, not the embedded one on 4022.
var (
	tcpPortNames = map[string]uint16{
		"ftp": 21, "ssh": 22, "smtp": 25, "dns": 53, "http": 80, "imaps": 993,
		"https": 443, "smb": 445, "mqtt": 1883, "mysql": 3306, "rdp": 3389,
		"postgres": 5432, "vnc": 5900,
	}
	udpPortNames = map[string]uint16{
		"dns": 53, "ntp": 123, "syslog": 514, "rdp": 3389, "mdns": 5353, "wireguard": 51820,
	}
)

func portNameTable(proto Protocol) map[string]uint16 {
	switch proto {
	case ProtocolTCP:
		return tcpPortNames
	case ProtocolUDP:
		return udpPortNames
	}
	return nil
}

// PortNames lists the service names known for tcp or udp, sorted.
func PortNames(proto Protocol) []string {
	table := portNameTable(proto)
	out := make([]string, 0, len(table))
	for n := range table {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// ExpandPortNames replaces service names in a tcp or udp rule's port list
// with their numbers ("rdp" -> "3389"); numbers and ranges stay as they
// are. An unknown name is an error.
func ExpandPortNames(proto Protocol, ports []string) ([]string, error) {
	if len(ports) == 0 {
		return ports, nil
	}
	table := portNameTable(proto)
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		name := strings.ToLower(strings.TrimSpace(p))
		if name == "" || (name[0] >= '0' && name[0] <= '9') {
			out = append(out, strings.TrimSpace(p))
			continue
		}
		n, ok := table[name]
		if !ok {
			if table == nil {
				return nil, fmt.Errorf("port adı %q yalnızca tcp ve udp kurallarında kullanılabilir", p)
			}
			return nil, fmt.Errorf("bilinmeyen port adı %q; bilinenler: %s", p, strings.Join(PortNames(proto), ", "))
		}
		out = append(out, strconv.Itoa(int(n)))
	}
	return out, nil
}

// PortLabel returns the known name of a single port for display, or "".
func PortLabel(proto Protocol, port string) string {
	for name, n := range portNameTable(proto) {
		if strconv.Itoa(int(n)) == port {
			return name
		}
	}
	return ""
}
