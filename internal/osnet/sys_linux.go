//go:build linux

package osnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// sysOps is how the Linux code touches the system. Tests replace it with a
// fake that records commands, so no test ever changes the host.
type sysOps struct {
	// run executes name with args (never through a shell); stdin may be nil.
	run func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
	// read returns a file's contents (used for /proc).
	read func(path string) ([]byte, error)
	// lookPath reports whether a program is installed.
	lookPath func(file string) (string, error)
}

// hostOps works on the real system.
// Tools are found only in the system folders (F-125, toolpath.go).
var hostOps = sysOps{run: runCommand, read: os.ReadFile, lookPath: lookTool}

func runCommand(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd, err := toolCommand(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (o sysOps) has(program string) bool {
	_, err := o.lookPath(program)
	return err == nil
}

// validSysctlName reports whether an interface name is safe inside a
// sysctl key. Keys use the slash form, so names with dots (VLANs such as
// eth0.100) work; slashes, "=" and spaces never appear in kernel names.
func validSysctlName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, "/= \t\n\"'`$;&|\\")
}

// sysctlPath turns "net/ipv6/conf/eth0/accept_ra" into its /proc path.
func sysctlPath(key string) string { return "/proc/sys/" + key }

// sysctlGet reads one sysctl value through /proc.
func (o sysOps) sysctlGet(key string) (string, error) {
	data, err := o.read(sysctlPath(key))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", fmt.Errorf("empty sysctl %s", key)
	}
	return v, nil
}

// sysctlSet writes one sysctl value with the sysctl program.
func (o sysOps) sysctlSet(ctx context.Context, key, value string) error {
	if strings.ContainsAny(value, " \t\n=") || value == "" {
		return errors.New("invalid sysctl value")
	}
	_, err := o.run(ctx, nil, "sysctl", "-w", key+"="+value)
	return err
}

// rtfReject marks an unreachable route in /proc/net/ipv6_route.
const rtfReject = 0x0200

// ipv6DefaultInterfaces returns the interfaces that carry an IPv6 default
// route, except loopback, unreachable routes and the excluded interface.
// A host without IPv6 has none.
func (o sysOps) ipv6DefaultInterfaces(exclude string) []string {
	data, err := o.read("/proc/net/ipv6_route")
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		var flags uint64
		if _, err := fmt.Sscanf(f[8], "%x", &flags); err != nil || flags&rtfReject != 0 {
			continue
		}
		dev := f[9]
		if dev == "lo" || dev == exclude || seen[dev] || !validSysctlName(dev) {
			continue
		}
		seen[dev] = true
		out = append(out, dev)
	}
	return out
}

// ipv4DefaultInterfaces returns the interfaces with an IPv4 default route
// in the main table (/proc/net/route).
func (o sysOps) ipv4DefaultInterfaces() []string {
	data, err := o.read("/proc/net/route")
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		if dev := f[0]; !seen[dev] && validSysctlName(dev) {
			seen[dev] = true
			out = append(out, dev)
		}
	}
	return out
}
