//go:build linux

package sysinfo

import (
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/openscale/openscale/internal/posture"
)

// Linux collection reads /proc and /sys only; no program is run. Root-only
// files (the SMBIOS table, efivars on some systems) are skipped quietly
// when unreadable. Serial and UUID files under /sys/class/dmi/id are never
// opened.

func readLimited(path string, max int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, max))
	return string(data)
}

func readTrim(path string) string { return strings.TrimSpace(readLimited(path, 4096)) }

func collectDetail(d *Detail) {
	safely(func() { linuxOS(d) })
	var sm smbiosInfo
	safely(func() {
		if t := readLimited("/sys/firmware/dmi/tables/DMI", maxSMBIOS); t != "" {
			sm = parseSMBIOS([]byte(t))
		}
	})
	safely(func() { linuxCPU(d, sm) })
	safely(func() { linuxMemory(d, sm) })
	safely(func() { linuxBoard(d) })
	safely(func() { d.Board.TPM, d.Board.TPMVendor = tpmDetail() })
	safely(func() { d.GPUs, d.Displays = linuxDRM() })
	var disks map[string]int
	safely(func() { d.Disks, disks = linuxDisks() })
	safely(func() { d.Volumes = linuxVolumes(d.Disks, disks) })
	safely(func() { d.NICs = linuxNICs() })
	safely(func() { d.Battery = linuxBatteryNow() })
}

func collectLight(d *Detail) {
	safely(func() {
		if b := linuxBatteryNow(); b != nil {
			d.Battery = &Battery{Percent: b.Percent, State: b.State}
		}
	})
	safely(func() { d.Users = linuxUsers() })
}

// ---- operating system ----

func linuxOS(d *Detail) {
	pretty, name, version := parseOSRelease(readLimited("/etc/os-release", 64<<10))
	if pretty == "" {
		pretty, name, version = parseOSRelease(readLimited("/usr/lib/os-release", 64<<10))
	}
	d.OS.Name = pretty
	if d.OS.Name == "" {
		d.OS.Name = name
	}
	d.OS.Version = version
	d.OS.Kernel = readTrim("/proc/sys/kernel/osrelease")
	switch readTrim("/proc/sys/kernel/arch") {
	case "x86_64":
		d.OS.Arch = "amd64"
	case "aarch64":
		d.OS.Arch = "arm64"
	case "riscv64":
		d.OS.Arch = "riscv64"
	}
	for line := range strings.SplitSeq(readLimited("/proc/stat", 1<<20), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if t, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				d.OS.Boot = t
			}
			break
		}
	}
	var stx unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, "/", 0, unix.STATX_BTIME, &stx) == nil && stx.Mask&unix.STATX_BTIME != 0 && stx.Btime.Sec > 0 {
		d.OS.Installed = stx.Btime.Sec
	}
	d.OS.TZ = linuxTZ()
}

func linuxTZ() string {
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" {
		if i := strings.Index(tz, "zoneinfo/"); i >= 0 {
			return tz[i+len("zoneinfo/"):]
		}
		return tz
	}
	if tz := strings.TrimSpace(strings.SplitN(readLimited("/etc/timezone", 256), "\n", 2)[0]); tz != "" {
		return tz
	}
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(l, "zoneinfo/"); i >= 0 {
			return l[i+len("zoneinfo/"):]
		}
	}
	return ""
}

// ---- processor, memory, board ----

func linuxCPU(d *Detail, sm smbiosInfo) {
	ci := parseCPUInfo(readLimited("/proc/cpuinfo", 4<<20))
	c := &d.CPU
	c.Model = ci.model
	if c.Model == "" {
		c.Model = cleanFirmwareText(readTrim("/proc/device-tree/model"))
	}
	if ci.threads > 0 {
		c.Threads = ci.threads
	}
	c.Cores, c.Sockets = ci.cores, ci.sockets
	if c.Cores == 0 {
		c.Cores, c.Sockets = sysfsCores()
	}
	khz := func(name string) int {
		v, _ := strconv.Atoi(readTrim("/sys/devices/system/cpu/cpu0/cpufreq/" + name))
		return v / 1000
	}
	c.BaseMHz = khz("base_frequency")
	if c.BaseMHz == 0 && sm.cpuCurMHz > 0 {
		c.BaseMHz = sm.cpuCurMHz
	}
	c.MaxMHz = khz("cpuinfo_max_freq")
	if c.MaxMHz == 0 && sm.cpuMaxMHz > c.BaseMHz {
		c.MaxMHz = sm.cpuMaxMHz
	}
	if c.BaseMHz == 0 && c.MaxMHz == 0 {
		c.BaseMHz = ci.mhz
	}
	switch {
	case ci.flags["hypervisor"]:
		c.Virt = "hv"
	case ci.flags["vmx"] || ci.flags["svm"]:
		c.Virt = "on"
	case exists("/dev/kvm"):
		c.Virt = "on"
	case len(ci.flags) > 0 && (strings.HasPrefix(d.OS.Arch, "amd64") || d.OS.Arch == "386"):
		c.Virt = "off"
	}
}

// sysfsCores counts cores from the topology files (ARM has no core ids in
// /proc/cpuinfo).
func sysfsCores() (cores, sockets int) {
	dirs, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/topology")
	seen, pkgs := map[string]bool{}, map[string]bool{}
	for _, dir := range dirs {
		pkg := readTrim(dir + "/physical_package_id")
		core := readTrim(dir + "/core_id")
		if core == "" {
			continue
		}
		seen[pkg+"/"+readTrim(dir+"/cluster_id")+"/"+core] = true
		pkgs[pkg] = true
	}
	return len(seen), len(pkgs)
}

func linuxMemory(d *Detail, sm smbiosInfo) {
	for line := range strings.SplitSeq(readLimited("/proc/meminfo", 64<<10), "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			kb, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			d.Mem.Total = kb << 10
			break
		}
	}
	var sum uint64
	for _, m := range sm.modules {
		sum += m.Size
	}
	if sum > d.Mem.Total {
		d.Mem.Total = sum
	}
	d.Mem.Slots, d.Mem.Modules = sm.memSlots, sm.modules
}

func linuxBoard(d *Detail) {
	b := &d.Board
	dmi := func(name string) string { return cleanFirmwareText(readTrim("/sys/class/dmi/id/" + name)) }
	b.Vendor, b.Model = dmi("sys_vendor"), dmi("product_name")
	b.BoardVendor, b.BoardModel = dmi("board_vendor"), dmi("board_name")
	b.BIOSVendor, b.BIOSVersion = dmi("bios_vendor"), dmi("bios_version")
	b.BIOSDate = biosDate(dmi("bios_date"))
	if b.Model == "" {
		b.Model = cleanFirmwareText(strings.TrimRight(readTrim("/proc/device-tree/model"), "\x00"))
	}
	switch {
	case exists("/sys/firmware/efi"):
		b.Firmware = "uefi"
		v := readLimited("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", 16)
		if len(v) >= 5 {
			b.SecureBoot = map[bool]string{true: "on", false: "off"}[v[4] == 1]
		}
	case d.OS.Arch == "amd64" || d.OS.Arch == "386":
		b.Firmware, b.SecureBoot = "bios", "unsupported"
	}
}

// ---- graphics and displays ----

var cardRE = regexp.MustCompile(`^card[0-9]+$`)

func pciLookup(vendor, device string) string {
	vendor = strings.TrimPrefix(strings.ToLower(vendor), "0x")
	device = strings.TrimPrefix(strings.ToLower(device), "0x")
	for _, p := range []string{"/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids", "/usr/share/pci.ids"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		name := pciName(f, vendor, device)
		f.Close()
		if name != "" {
			return name
		}
	}
	if v, ok := map[string]string{"10de": "NVIDIA", "1002": "AMD", "8086": "Intel", "1af4": "Virtio", "15ad": "VMware", "1234": "QEMU", "1414": "Microsoft"}[vendor]; ok {
		return v + " [" + vendor + ":" + device + "]"
	}
	if vendor != "" && device != "" {
		return "PCI " + vendor + ":" + device
	}
	return ""
}

func linuxDRM() ([]GPU, []Display) {
	entries, err := os.ReadDir("/sys/class/drm")
	if err != nil {
		return nil, nil
	}
	var gpus []GPU
	var displays []Display
	for _, e := range entries {
		name := e.Name()
		base := "/sys/class/drm/" + name
		if cardRE.MatchString(name) {
			vendor, device := readTrim(base+"/device/vendor"), readTrim(base+"/device/device")
			if vendor == "" {
				continue
			}
			g := GPU{Model: pciLookup(vendor, device)}
			if drv, err := os.Readlink(base + "/device/driver"); err == nil {
				g.Driver = filepath.Base(drv)
				if v := readTrim("/sys/module/" + g.Driver + "/version"); v != "" {
					g.Driver += " " + v
				}
			}
			g.VRAM, _ = strconv.ParseUint(readTrim(base+"/device/mem_info_vram_total"), 10, 64)
			gpus = append(gpus, g)
			continue
		}
		if !strings.HasPrefix(name, "card") || !strings.Contains(name, "-") || readTrim(base+"/status") != "connected" {
			continue
		}
		if disp, ok := parseEDID([]byte(readLimited(base+"/edid", 32<<10))); ok {
			displays = append(displays, disp)
			continue
		}
		mode := strings.SplitN(readLimited(base+"/modes", 4096), "\n", 2)[0]
		if w, h, ok := strings.Cut(mode, "x"); ok {
			wi, _ := strconv.Atoi(w)
			hi, _ := strconv.Atoi(strings.TrimRightFunc(h, func(r rune) bool { return r < '0' || r > '9' }))
			if wi > 0 && hi > 0 {
				displays = append(displays, Display{W: wi, H: hi})
			}
		}
	}
	return gpus, displays
}

// ---- disks and volumes ----

func skipBlock(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd", "zd", "mtdblock"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// linuxDisks lists whole disks; the map gives each disk name's Index.
func linuxDisks() ([]Disk, map[string]int) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, nil
	}
	idx := map[string]int{}
	var out []Disk
	for _, e := range entries {
		name := e.Name()
		if skipBlock(name) || len(out) >= maxDisks {
			continue
		}
		base := "/sys/block/" + name
		sectors, _ := strconv.ParseUint(readTrim(base+"/size"), 10, 64)
		if sectors == 0 {
			continue
		}
		k := Disk{Index: len(out), Size: sectors * 512, Removable: readTrim(base+"/removable") == "1"}
		k.Model = readTrim(base + "/device/model")
		if v := readTrim(base + "/device/vendor"); v != "" && !strings.EqualFold(v, "ATA") {
			k.Model = joinModel(v, k.Model)
		}
		if k.Model == "" {
			k.Model = readTrim(base + "/device/name") // MMC
		}
		real, _ := filepath.EvalSymlinks(base)
		lower := strings.ToLower(real)
		switch {
		case strings.HasPrefix(name, "nvme"):
			k.Bus = "nvme"
		case strings.HasPrefix(name, "mmcblk"):
			k.Bus = "mmc"
		case strings.HasPrefix(name, "vd") || strings.Contains(lower, "/virtio"):
			k.Bus = "virtio"
		case strings.HasPrefix(name, "xvd") || strings.Contains(lower, "vmbus") || strings.Contains(lower, "/hv_") || virtualDiskModel(k.Model):
			k.Bus = "virtual"
		case strings.Contains(lower, "/usb"):
			k.Bus, k.Removable = "usb", true
		case strings.Contains(lower, "/ata"):
			k.Bus = "sata"
		case strings.Contains(lower, "/host"):
			k.Bus = "scsi"
		}
		switch {
		case k.Bus == "nvme":
			k.Type = "nvme"
		case k.Bus == "virtual" || k.Bus == "virtio":
			// A hypervisor's rotational flag says nothing about the medium.
		case readTrim(base+"/queue/rotational") == "1":
			k.Type = "hdd"
		case readTrim(base+"/queue/rotational") == "0":
			k.Type = "ssd"
		}
		idx[name] = k.Index
		out = append(out, k)
	}
	return out, idx
}

// blockName returns the kernel name of block device "major:minor".
func blockName(devnum string) string {
	real, err := filepath.EvalSymlinks("/sys/dev/block/" + devnum)
	if err != nil {
		return ""
	}
	return filepath.Base(real)
}

// diskOf finds the whole disk under a partition or device-mapper device.
func diskOf(name string, disks map[string]int, depth int) int {
	if depth > 8 || name == "" || strings.ContainsAny(name, "/\\") {
		return -1
	}
	if i, ok := disks[name]; ok {
		return i
	}
	if exists("/sys/class/block/" + name + "/partition") {
		real, err := filepath.EvalSymlinks("/sys/class/block/" + name)
		if err == nil {
			return diskOf(filepath.Base(filepath.Dir(real)), disks, depth+1)
		}
	}
	slaves, err := os.ReadDir("/sys/class/block/" + name + "/slaves")
	if err == nil && len(slaves) > 0 {
		return diskOf(slaves[0].Name(), disks, depth+1)
	}
	return -1
}

func linuxVolumes(list []Disk, disks map[string]int) []Volume {
	var out []Volume
	for _, m := range parseMountInfo(readLimited("/proc/self/mountinfo", 4<<20)) {
		if len(out) >= maxVolumes {
			break
		}
		v := Volume{Mount: MaskMount(m.mount), FS: m.fstype, Disk: -1}
		var st unix.Statfs_t
		if unix.Statfs(m.mount, &st) == nil && st.Bsize > 0 {
			bs := uint64(st.Bsize)
			v.Size, v.Free = st.Blocks*bs, st.Bavail*bs
		}
		devnum := m.devnum
		if strings.HasPrefix(devnum, "0:") && strings.HasPrefix(m.source, "/dev/") {
			// btrfs and others report an anonymous device; the source
			// names the real one.
			var s unix.Stat_t
			if unix.Stat(m.source, &s) == nil && s.Mode&unix.S_IFMT == unix.S_IFBLK {
				devnum = strconv.FormatUint(uint64(unix.Major(s.Rdev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(s.Rdev)), 10)
			}
		}
		switch posture.DeviceEncryption(devnum) {
		case posture.On:
			v.Encrypted = "on"
		case posture.Off:
			v.Encrypted = "off"
		}
		if !strings.HasPrefix(devnum, "0:") {
			v.Disk = diskOf(blockName(devnum), disks, 0)
			if v.Disk >= 0 && v.Disk < len(list) {
				v.Removable = list[v.Disk].Removable
			}
		}
		out = append(out, v)
	}
	return out
}

// ---- network ----

func linuxNICs() []NIC {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	routes := parseDefaultRoutes(readLimited("/proc/net/route", 1<<20), readLimited("/proc/net/ipv6_route", 1<<20))
	wifi := parseWireless(readLimited("/proc/net/wireless", 64<<10))
	var out []NIC
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || strings.ContainsAny(ifc.Name, "/\\") || ifc.Name == "." || ifc.Name == ".." {
			continue
		}
		base := "/sys/class/net/" + ifc.Name
		hardware := exists(base + "/device")
		oper := readTrim(base + "/operstate")
		up := oper == "up" || (oper == "unknown" && ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagRunning != 0)
		if !hardware && !up {
			continue
		}
		n := NIC{Name: ifc.Name, Up: up, Gateway: routes[ifc.Name]}
		devtype := ""
		for line := range strings.SplitSeq(readLimited(base+"/uevent", 4096), "\n") {
			if v, ok := strings.CutPrefix(line, "DEVTYPE="); ok {
				devtype = v
			}
		}
		switch {
		case exists(base+"/wireless") || exists(base+"/phy80211") || devtype == "wlan":
			n.Type = "wifi"
		case devtype == "wwan":
			n.Type = "cellular"
		case devtype == "bluetooth" || strings.HasPrefix(ifc.Name, "bnep"):
			n.Type = "bluetooth"
		case !hardware:
			n.Type = "virtual"
		case readTrim(base+"/type") == "1":
			n.Type = "ethernet"
		default:
			n.Type = "other"
		}
		if hardware && exists(base+"/device/vendor") {
			n.Model = pciLookup(readTrim(base+"/device/vendor"), readTrim(base+"/device/device"))
		}
		n.OUI, n.RandomMAC = OUI(ifc.HardwareAddr)
		if up {
			if s, err := strconv.ParseInt(readTrim(base+"/speed"), 10, 64); err == nil && s > 0 {
				n.Speed = uint64(s)
			}
		}
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
		if q, ok := wifi[ifc.Name]; ok && n.Type == "wifi" {
			n.Signal = q
		}
		out = append(out, n)
		if len(out) >= maxNICs {
			break
		}
	}
	return out
}

// ---- battery and sessions ----

func linuxBatteryNow() *Battery {
	entries, err := os.ReadDir("/sys/class/power_supply")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		base := "/sys/class/power_supply/" + e.Name()
		if readTrim(base+"/type") != "Battery" || readTrim(base+"/scope") == "Device" {
			continue // peripheral batteries (mice, headsets) are not the system's
		}
		if b := linuxBattery(func(name string) string { return readTrim(base + "/" + name) }); b != nil {
			return b
		}
	}
	return nil
}

func linuxUsers() int {
	if entries, err := os.ReadDir("/run/systemd/sessions"); err == nil {
		uids := map[string]bool{}
		for _, e := range entries {
			if e.IsDir() || strings.Contains(e.Name(), ".") {
				continue
			}
			if uid := parseSessionFile(readLimited("/run/systemd/sessions/"+e.Name(), 64<<10)); uid != "" {
				uids[uid] = true
			}
		}
		return len(uids)
	}
	for _, p := range []string{"/run/utmp", "/var/run/utmp"} {
		if exists(p) {
			return parseUtmpUsers([]byte(readLimited(p, 4<<20)))
		}
	}
	return -1
}
