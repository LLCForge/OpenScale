//go:build darwin

package sysinfo

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// macOS collection: sysctl for the system and processor, one
// system_profiler call (mini detail level, 30 s time-out, cached for 30
// minutes) for graphics, displays, storage, power and memory modules, and
// the routing table for default routes. Disk encryption (FileVault) and
// logged-on users are not read and stay unknown.

const profilerTTL = 30 * time.Minute

var profiler struct {
	mu   sync.Mutex
	at   time.Time
	data macProfile
}

func cachedProfile() macProfile {
	profiler.mu.Lock()
	defer profiler.mu.Unlock()
	if !profiler.at.IsZero() && time.Since(profiler.at) < profilerTTL {
		return profiler.data
	}
	profiler.at = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/system_profiler", "-json", "-detailLevel", "mini",
		"SPHardwareDataType", "SPDisplaysDataType", "SPStorageDataType", "SPPowerDataType", "SPMemoryDataType", "SPNetworkDataType")
	var out bytes.Buffer
	cmd.Stdout = &limitedBuffer{b: &out, n: 8 << 20}
	if cmd.Run() == nil {
		profiler.data = parseSystemProfiler(out.Bytes())
	}
	return profiler.data
}

type limitedBuffer struct {
	b *bytes.Buffer
	n int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func sysctlInt(name string) int {
	v, err := unix.SysctlUint32(name)
	if err != nil {
		return 0
	}
	return int(v)
}

func sysctlU64(name string) uint64 {
	v, err := unix.SysctlUint64(name)
	if err != nil {
		return 0
	}
	return v
}

func collectDetail(d *Detail) {
	safely(func() { darwinOS(d) })
	safely(func() { darwinCPU(d) })
	p := macProfile{}
	safely(func() { p = cachedProfile() })
	d.Mem.Total = sysctlU64("hw.memsize")
	d.Mem.Modules = p.modules
	d.Board.Vendor = "Apple"
	d.Board.Model = strings.TrimSpace(p.model + " " + p.modelID)
	if d.Board.Model == "" {
		d.Board.Model, _ = unix.Sysctl("hw.model")
	}
	d.Board.BIOSVersion = p.firmware
	d.GPUs, d.Displays, d.Disks, d.Volumes, d.Battery = p.gpus, p.displays, p.disks, p.volumes, p.battery
	safely(func() { d.NICs = darwinNICs(p.nicTypes) })
}

func collectLight(*Detail) {}

func darwinOS(d *Detail) {
	d.OS.Name = "macOS"
	d.OS.Version, _ = unix.Sysctl("kern.osproductversion")
	d.OS.Build, _ = unix.Sysctl("kern.osversion")
	d.OS.Kernel, _ = unix.Sysctl("kern.osrelease")
	if sysctlInt("sysctl.proc_translated") == 1 {
		d.OS.Arch = "arm64" // an amd64 build under Rosetta
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil && tv.Sec > 0 {
		d.OS.Boot = tv.Sec
	}
	var st syscall.Stat_t
	if syscall.Stat("/var/db/.AppleSetupDone", &st) == nil && st.Birthtimespec.Sec > 0 {
		d.OS.Installed = st.Birthtimespec.Sec
	}
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(l, "zoneinfo/"); i >= 0 {
			d.OS.TZ = l[i+len("zoneinfo/"):]
		}
	}
}

func darwinCPU(d *Detail) {
	c := &d.CPU
	c.Model, _ = unix.Sysctl("machdep.cpu.brand_string")
	c.Cores, c.Threads = sysctlInt("hw.physicalcpu"), sysctlInt("hw.logicalcpu")
	c.Sockets = sysctlInt("hw.packages")
	c.BaseMHz = int(sysctlU64("hw.cpufrequency") / 1_000_000)
	c.MaxMHz = int(sysctlU64("hw.cpufrequency_max") / 1_000_000)
	if c.MaxMHz <= c.BaseMHz {
		c.MaxMHz = 0
	}
	switch {
	case sysctlInt("kern.hv_vmm_present") == 1:
		c.Virt = "hv"
	case sysctlInt("kern.hv_support") == 1:
		c.Virt = "on"
	default:
		c.Virt = "off"
	}
}

// defaultRouteIfaces returns the interface indexes of default routes.
func defaultRouteIfaces() map[int]bool {
	out := map[int]bool{}
	b, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return out
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return out
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_DST {
			continue
		}
		switch a := rm.Addrs[syscall.RTAX_DST].(type) {
		case *route.Inet4Addr:
			if a.IP == [4]byte{} {
				out[rm.Index] = true
			}
		case *route.Inet6Addr:
			if a.IP == [16]byte{} {
				out[rm.Index] = true
			}
		}
	}
	return out
}

func darwinNICs(types map[string]string) []NIC {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	gw := defaultRouteIfaces()
	var out []NIC
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		up := ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagRunning != 0
		t, known := types[ifc.Name]
		if !known {
			if !up {
				continue
			}
			t = "virtual" // utun, awdl, llw, bridge without a network service
		}
		n := NIC{Name: ifc.Name, Type: t, Up: up, Gateway: gw[ifc.Index]}
		n.OUI, n.RandomMAC = OUI(ifc.HardwareAddr)
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if v4 := ipn.IP.To4(); v4 != nil {
					n.IPv4 = append(n.IPv4, v4.String())
				} else if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					if s := PrivateIPv6(ip); s != "" {
						n.IPv6 = append(n.IPv6, s)
					}
				}
			}
		}
		out = append(out, n)
		if len(out) >= maxNICs {
			break
		}
	}
	return out
}
