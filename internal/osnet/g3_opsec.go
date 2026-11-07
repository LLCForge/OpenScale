package osnet

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Network opsec system changes of group G3 (ADR-0189):
//
//   - #621 DHCP host name: on an untrusted network the computer name in
//     the DHCP request (option 12) tells the network who is there
//     ("Ayse-MacBook-Pro"). A random, ordinary-looking name is sent
//     instead while the owner turns it on.
//   - #625 WebRTC/STUN: a browser's WebRTC asks STUN servers for the
//     public address outside the tunnel. While the tunnel is on, UDP to
//     STUN ports (and, on Linux, any UDP carrying the STUN magic cookie)
//     is refused on every interface except the tunnel.
//
// Both are plans first: Plan* functions only build the commands, and
// nothing runs unless the caller (the CLI, after the owner asked) passes
// them to RunPlan. Tests never run them.

// Command is one system tool invocation (argv, never a shell).
type Command struct {
	Tool string   `json:"tool"`
	Args []string `json:"args"`
	// Stdin is passed to the tool (nft and pfctl rule sets).
	Stdin string `json:"stdin,omitempty"`
}

func (c Command) String() string {
	s := c.Tool + " " + strings.Join(c.Args, " ")
	if c.Stdin != "" {
		s += "  <<< " + strings.ReplaceAll(strings.TrimSpace(c.Stdin), "\n", " ; ")
	}
	return s
}

// Runner runs one command; tests pass a recorder.
type Runner func(ctx context.Context, c Command) error

// RunPlan runs cmds in order and stops at the first error.
func RunPlan(ctx context.Context, cmds []Command, r Runner) error {
	if r == nil {
		r = systemRunner
	}
	for _, c := range cmds {
		if err := r(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// systemRunner runs a system tool by absolute path (F-125).
func systemRunner(ctx context.Context, c Command) error {
	if c.Stdin == "" {
		return run(ctx, c.Tool, c.Args...)
	}
	cmd, err := toolCommand(ctx, c.Tool, c.Args...)
	if err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(c.Stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", c.Tool, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---- #621 DHCP host name ----

const hostAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// RandomHostname returns an ordinary-looking random host name for goos:
// "DESKTOP-XXXXXXX" (Windows), "MacBook-XXXX" (macOS) or "linux-xxxxxx".
func RandomHostname(goos string, r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	pick := func(n int) (string, error) {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		for i := range b {
			b[i] = hostAlphabet[int(b[i])%len(hostAlphabet)]
		}
		return string(b), nil
	}
	switch goos {
	case "windows":
		s, err := pick(7)
		return "DESKTOP-" + s, err
	case "darwin":
		s, err := pick(4)
		return "MacBook-" + s, err
	default:
		s, err := pick(6)
		return "linux-" + strings.ToLower(s), err
	}
}

// ErrOpsecPlan is wrapped by plan validation errors.
var ErrOpsecPlan = errors.New("sistem değişikliği planı geçersiz")

// validHostname accepts a DNS label (RFC 1123), at most 15 characters on
// Windows (NetBIOS limit).
func validHostname(goos, s string) bool {
	max := 63
	if goos == "windows" {
		max = 15
	}
	if s == "" || len(s) > max || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// validConnection accepts a NetworkManager connection or macOS service
// name: printable, no control characters, at most 64 bytes.
func validConnection(s string) bool {
	if s == "" || len(s) > 64 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// DHCPHostnamePlan returns the commands that make the DHCP client send
// name, and the commands that restore original (the name sent before;
// empty restores the system default). conn is the NetworkManager
// connection (Linux) or the network interface such as "en0" (macOS); it
// is unused on Windows, where the name is per computer and applies from
// the next DHCP renewal.
func DHCPHostnamePlan(goos, conn, name, original string) (apply, restore []Command, err error) {
	if !validHostname(goos, name) {
		return nil, nil, fmt.Errorf("%w: ad %q geçerli bir ana makine adı değil", ErrOpsecPlan, name)
	}
	if original != "" && !validHostname(goos, original) {
		return nil, nil, fmt.Errorf("%w: eski ad %q geçerli değil", ErrOpsecPlan, original)
	}
	switch goos {
	case "linux":
		if !validConnection(conn) {
			return nil, nil, fmt.Errorf("%w: NetworkManager bağlantı adı gerekli", ErrOpsecPlan)
		}
		set := func(v string) []Command {
			return []Command{
				{Tool: "nmcli", Args: []string{"connection", "modify", conn, "ipv4.dhcp-hostname", v, "ipv6.dhcp-hostname", v}},
				{Tool: "nmcli", Args: []string{"connection", "up", conn}},
			}
		}
		return set(name), set(original), nil
	case "darwin":
		if !validConnection(conn) {
			return nil, nil, fmt.Errorf("%w: ağ arayüzü (ör. en0) gerekli", ErrOpsecPlan)
		}
		set := func(v string) []Command {
			return []Command{
				{Tool: "scutil", Args: []string{"--set", "LocalHostName", v}},
				{Tool: "ipconfig", Args: []string{"set", conn, "DHCP"}},
			}
		}
		if original == "" {
			return set(name), nil, nil
		}
		return set(name), set(original), nil
	case "windows":
		const key = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
		set := func(v string) []Command {
			return []Command{
				{Tool: "reg", Args: []string{"add", key, "/v", "NV Hostname", "/t", "REG_SZ", "/d", v, "/f"}},
				{Tool: "ipconfig", Args: []string{"/renew"}},
			}
		}
		if original == "" {
			return set(name), nil, nil
		}
		return set(name), set(original), nil
	}
	return nil, nil, fmt.Errorf("%w: %s desteklenmiyor", ErrOpsecPlan, goos)
}

// ---- #625 WebRTC/STUN ----

// STUNPorts are the UDP ports of STUN and TURN (RFC 8489, RFC 8656) and
// the range public WebRTC STUN servers commonly use.
var STUNPorts = []string{"3478", "3479", "5349", "5350", "19302-19309"}

// stunTable and stunAnchor name what the plans install.
const (
	stunTable  = "openscale_stun"
	stunAnchor = "com.openscale/stun" // evaluated only where "com.openscale" calls anchor "stun" (ADR-0189)
	stunRule   = "OpenScale WebRTC STUN engeli"
	// stunCookie is the STUN magic cookie at UDP payload offset 4
	// (transport header bit offset 96).
	stunCookie = "0x2112a442"
)

func validIface(s string) bool {
	return s != "" && len(s) <= 32 && !strings.ContainsAny(s, " \"'\t\n;&|{}$`\\")
}

// STUNBlockPlan returns the commands that refuse STUN outside the tunnel
// interface tunIface, and the commands that remove the block.
func STUNBlockPlan(goos, tunIface string) (apply, remove []Command, err error) {
	if !validIface(tunIface) {
		return nil, nil, fmt.Errorf("%w: tünel arayüzü adı %q geçersiz", ErrOpsecPlan, tunIface)
	}
	ports := strings.Join(STUNPorts, ", ")
	switch goos {
	case "linux":
		rules := fmt.Sprintf(`table inet %[1]s {
	chain out {
		type filter hook output priority 0; policy accept;
		oifname != "%[2]s" udp dport { %[3]s } counter drop
		oifname != "%[2]s" meta l4proto udp @th,96,32 %[4]s counter drop
	}
}
`, stunTable, tunIface, ports, stunCookie)
		return []Command{{Tool: "nft", Args: []string{"-f", "-"}, Stdin: rules}},
			[]Command{{Tool: "nft", Args: []string{"delete", "table", "inet", stunTable}}}, nil
	case "darwin":
		pfPorts := strings.ReplaceAll(strings.Join(STUNPorts, " "), "-", ":")
		rules := fmt.Sprintf("block drop out quick on ! %s proto udp from any to any port { %s }\n", tunIface, pfPorts)
		return []Command{{Tool: "pfctl", Args: []string{"-a", stunAnchor, "-f", "-"}, Stdin: rules}},
			[]Command{{Tool: "pfctl", Args: []string{"-a", stunAnchor, "-F", "rules"}}}, nil
	case "windows":
		// Windows Firewall cannot match the payload or exclude one
		// adapter by name; the rule covers LAN and wireless adapters, so
		// the Wintun adapter (and with it the tunnel) is not affected.
		winPorts := strings.ReplaceAll(strings.Join(STUNPorts, ","), " ", "")
		return []Command{{Tool: "netsh", Args: []string{"advfirewall", "firewall", "add", "rule", "name=" + stunRule,
				"dir=out", "action=block", "protocol=UDP", "remoteport=" + winPorts, "interfacetype=lan,wireless"}}},
			[]Command{{Tool: "netsh", Args: []string{"advfirewall", "firewall", "delete", "rule", "name=" + stunRule}}}, nil
	}
	return nil, nil, fmt.Errorf("%w: %s desteklenmiyor", ErrOpsecPlan, goos)
}
