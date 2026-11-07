//go:build windows

package winapp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	psTimeout    = 45 * time.Second
	maxPSOutput  = 1 << 20
	maxListeners = 300
)

// Built-in Windows rule ids (language independent) that open RDP and the
// OpenSSH server to every address.
var (
	rdpBuiltinRules = []string{"RemoteDesktop-UserMode-In-TCP", "RemoteDesktop-UserMode-In-UDP", "RemoteDesktop-Shadow-In-TCP"}
	sshBuiltinRules = []string{"OpenSSH-Server-In-TCP"}
	rdpOwnRules     = []string{"OpenScale-RDP-TCP", "OpenScale-RDP-UDP"}
	sshOwnRules     = []string{"OpenScale-SSH-TCP"}
)

// RemoteAccessStatus describes remote desktop and SSH on this computer.
type RemoteAccessStatus struct {
	RDPEnabled   bool
	RDPPort      int
	RDPScoped    bool
	SSHInstalled bool
	SSHPort      int
	SSHScoped    bool
}

// Listener is a socket accepting connections or datagrams.
type Listener struct {
	Proto   string `json:"p"`
	Address string `json:"a"`
	Port    int    `json:"n"`
	Process string `json:"s"`
}

// GetRemoteAccess reads whether RDP and SSH are on and whether their
// firewall rules are limited to OpenScale.
func GetRemoteAccess() (RemoteAccessStatus, error) {
	st := RemoteAccessStatus{RDPPort: rdpPort(), SSHPort: sshPort()}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, registry.QUERY_VALUE); err == nil {
		deny, _, err := k.GetIntegerValue("fDenyTSConnections")
		st.RDPEnabled = err == nil && deny == 0
		k.Close()
	}
	st.SSHInstalled = serviceExists("sshd")

	names := append(append(append(append([]string{}, rdpBuiltinRules...), sshBuiltinRules...), rdpOwnRules...), sshOwnRules...)
	script := "$r=@{}; foreach($n in @(" + psList(names) + ")){ $x=Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue; if($x){ $r[$n]=[string]$x.Enabled } }; $r | ConvertTo-Json -Compress"
	out, err := runPowerShell(script)
	if err != nil {
		return st, err
	}
	rules := map[string]string{}
	if len(bytes.TrimSpace(out)) > 0 {
		if err := json.Unmarshal(out, &rules); err != nil {
			return st, fmt.Errorf("güvenlik duvarı durumu okunamadı: %w", err)
		}
	}
	st.RDPScoped = scoped(rules, rdpOwnRules[0], rdpBuiltinRules)
	st.SSHScoped = scoped(rules, sshOwnRules[0], sshBuiltinRules)
	return st, nil
}

// scoped: our rule is on and no built-in rule still allows every address.
func scoped(rules map[string]string, own string, builtins []string) bool {
	if rules[own] != "True" {
		return false
	}
	for _, b := range builtins {
		if rules[b] == "True" {
			return false
		}
	}
	return true
}

// SetRemoteAccessScope limits RDP ("rdp") or SSH ("ssh") to the overlay
// prefixes, or restores the Windows default rules. Only the rules named
// above are touched.
func SetRemoteAccessScope(service string, overlayOnly bool, prefixes []netip.Prefix) error {
	if !IsElevated() {
		return errFirewallNeedsAdmin
	}
	var own, builtins []string
	var port int
	var udp bool
	switch service {
	case "rdp":
		own, builtins, port, udp = rdpOwnRules, rdpBuiltinRules, rdpPort(), true
	case "ssh":
		own, builtins, port = sshOwnRules, sshBuiltinRules, sshPort()
	default:
		return errors.New("bilinmeyen servis")
	}
	if port < 1 || port > 65535 {
		return errors.New("geçersiz port")
	}
	var b strings.Builder
	b.WriteString("Remove-NetFirewallRule -Name " + psList(own) + " -ErrorAction SilentlyContinue; ")
	if overlayOnly {
		remote, err := remoteList(prefixes)
		if err != nil {
			return err
		}
		label := strings.ToUpper(service)
		fmt.Fprintf(&b, "New-NetFirewallRule -Name '%s' -DisplayName 'OpenScale %s (TCP)' -Group 'OpenScale' -Direction Inbound -Protocol TCP -LocalPort %d -RemoteAddress %s -Action Allow -Profile Any | Out-Null; ", own[0], label, port, remote)
		if udp {
			fmt.Fprintf(&b, "New-NetFirewallRule -Name '%s' -DisplayName 'OpenScale %s (UDP)' -Group 'OpenScale' -Direction Inbound -Protocol UDP -LocalPort %d -RemoteAddress %s -Action Allow -Profile Any | Out-Null; ", own[1], label, port, remote)
		}
		b.WriteString("Get-NetFirewallRule -Name " + psList(builtins) + " -ErrorAction SilentlyContinue | Disable-NetFirewallRule")
	} else {
		// Back to the Windows default: the built-in rules open the service
		// to every address again.
		b.WriteString("Get-NetFirewallRule -Name " + psList(builtins) + " -ErrorAction SilentlyContinue | Enable-NetFirewallRule")
	}
	if _, err := runPowerShell(b.String()); err != nil {
		return fmt.Errorf("güvenlik duvarı güncellenemedi: %w", err)
	}
	return nil
}

// ListeningPorts lists TCP listeners and bound UDP ports below the dynamic
// range, with the owning process name.
func ListeningPorts() ([]Listener, error) {
	script := `$p=@{}; Get-Process | ForEach-Object { $p[$_.Id]=$_.ProcessName }; ` +
		`$t=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{p='tcp';a=[string]$_.LocalAddress;n=[int]$_.LocalPort;s=[string]$p[[int]$_.OwningProcess]} }); ` +
		`$u=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object { [pscustomobject]@{p='udp';a=[string]$_.LocalAddress;n=[int]$_.LocalPort;s=[string]$p[[int]$_.OwningProcess]} }); ` +
		`ConvertTo-Json -Compress -InputObject @($t + $u)`
	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}
	var ls []Listener
	if err := json.Unmarshal(bytes.TrimSpace(out), &ls); err != nil {
		return nil, fmt.Errorf("port listesi okunamadı: %w", err)
	}
	seen := map[string]bool{}
	outList := make([]Listener, 0, len(ls))
	for _, l := range ls {
		key := l.Proto + "|" + l.Address + "|" + strconv.Itoa(l.Port)
		if seen[key] || l.Port < 1 || l.Port > 65535 {
			continue
		}
		seen[key] = true
		l.Process = menuLabel(l.Process)
		outList = append(outList, l)
		if len(outList) >= maxListeners {
			break
		}
	}
	return outList, nil
}

func remoteList(prefixes []netip.Prefix) (string, error) {
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() || p.Bits() == 0 {
			return "", errors.New("geçersiz ağ aralığı")
		}
		// netip renders only digits, hex letters, '.', ':' and '/'.
		parts = append(parts, "'"+p.Masked().String()+"'")
	}
	if len(parts) == 0 {
		return "", errors.New("ağ aralığı yok")
	}
	return strings.Join(parts, ","), nil
}

// psList renders constant rule ids as a PowerShell array literal.
func psList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "'" + n + "'"
	}
	return strings.Join(quoted, ",")
}

func rdpPort() int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, registry.QUERY_VALUE)
	if err != nil {
		return 3389
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("PortNumber"); err == nil && v > 0 && v <= 65535 {
		return int(v)
	}
	return 3389
}

// sshPort reads the first Port line of the Windows OpenSSH server config.
func sshPort() int {
	f, err := os.Open(filepath.Join(os.Getenv("ProgramData"), "ssh", "sshd_config"))
	if err != nil {
		return 22
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 2 && strings.EqualFold(fields[0], "Port") {
			if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 && n <= 65535 {
				return n
			}
		}
	}
	return 22
}

func serviceExists(name string) bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// runPowerShell runs a fixed script with Windows PowerShell from System32,
// without profile or window, and returns stdout.
func runPowerShell(script string) ([]byte, error) {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	exe := filepath.Join(sysDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, errors.New("PowerShell zamanında yanıt vermedi")
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > maxNetshOutput {
			msg = msg[:maxNetshOutput]
		}
		return nil, fmt.Errorf("PowerShell: %s", msg)
	}
	if stdout.Len() > maxPSOutput {
		return nil, errors.New("PowerShell çıktısı çok büyük")
	}
	return stdout.Bytes(), nil
}
