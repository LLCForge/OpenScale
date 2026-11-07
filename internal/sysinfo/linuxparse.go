package sysinfo

import (
	"bufio"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
)

// Parsers for Linux /proc and /sys text. They take the file contents, so
// they are tested on every system.

type cpuInfo struct {
	model                   string
	sockets, cores, threads int
	flags                   map[string]bool
	mhz                     int
}

// parseCPUInfo reads /proc/cpuinfo: model name, logical processors, and
// physical cores as distinct (physical id, core id) pairs.
func parseCPUInfo(text string) cpuInfo {
	c := cpuInfo{flags: map[string]bool{}}
	pkgs := map[string]bool{}
	cores := map[string]bool{}
	phys, core := "", ""
	flush := func() {
		if core != "" {
			cores[phys+"/"+core] = true
			pkgs[phys] = true
		}
		phys, core = "", ""
	}
	for line := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok {
			if strings.TrimSpace(line) == "" {
				flush()
			}
			continue
		}
		switch k {
		case "processor":
			c.threads++
		case "model name":
			if c.model == "" {
				c.model = v
			}
		case "physical id":
			phys = v
		case "core id":
			core = v
		case "cpu MHz":
			if c.mhz == 0 {
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					c.mhz = int(f + 0.5)
				}
			}
		case "flags", "Features":
			if len(c.flags) == 0 {
				for _, f := range strings.Fields(v) {
					c.flags[f] = true
				}
			}
		}
	}
	flush()
	c.cores, c.sockets = len(cores), len(pkgs)
	return c
}

// parseOSRelease returns PRETTY_NAME, NAME and VERSION_ID.
func parseOSRelease(text string) (pretty, name, version string) {
	for line := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "PRETTY_NAME":
			pretty = v
		case "NAME":
			name = v
		case "VERSION_ID":
			version = v
		}
	}
	return pretty, name, version
}

type mountEntry struct {
	devnum, mount, fstype, source string
}

// diskFS are the file systems reported as volumes; pseudo, network and
// overlay file systems are left out.
var diskFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "vfat": true, "exfat": true,
	"ntfs": true, "ntfs3": true, "fuseblk": true, "f2fs": true, "zfs": true, "jfs": true, "reiserfs": true,
	"bcachefs": true, "hfsplus": true, "nilfs2": true,
}

// parseMountInfo reads /proc/self/mountinfo and keeps one entry per block
// device (the shortest mount point), in mount order.
func parseMountInfo(text string) []mountEntry {
	var out []mountEntry
	idx := map[string]int{}
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(f) < 5 || sep < 0 || sep+1 >= len(f) {
			continue
		}
		e := mountEntry{devnum: f[2], mount: unescapeMount(f[4]), fstype: f[sep+1]}
		if sep+2 < len(f) {
			e.source = f[sep+2]
		}
		if !diskFS[e.fstype] || strings.HasPrefix(e.mount, "/snap/") || strings.HasPrefix(e.mount, "/var/lib/docker/") {
			continue
		}
		if i, ok := idx[e.devnum]; ok {
			if len(e.mount) < len(out[i].mount) {
				out[i].mount = e.mount
			}
			continue
		}
		idx[e.devnum] = len(out)
		out = append(out, e)
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for space) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseDefaultRoutes returns the interfaces holding a default route in
// /proc/net/route and /proc/net/ipv6_route.
func parseDefaultRoutes(v4, v6 string) map[string]bool {
	out := map[string]bool{}
	for line := range strings.SplitSeq(v4, "\n") {
		f := strings.Fields(line)
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			out[f[0]] = true
		}
	}
	for line := range strings.SplitSeq(v6, "\n") {
		f := strings.Fields(line)
		if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			out[f[9]] = true
		}
	}
	return out
}

// parseWireless returns the link quality of each interface in
// /proc/net/wireless as a percentage (the kernel scale is 0-70).
func parseWireless(text string) map[string]int {
	out := map[string]int{}
	for line := range strings.SplitSeq(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		f := strings.Fields(rest)
		if !ok || len(f) < 2 {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSuffix(f[1], "."), 64)
		if err != nil || q < 0 {
			continue
		}
		out[strings.TrimSpace(name)] = min(int(q*100/70+0.5), 100)
	}
	return out
}

// pciName looks a PCI vendor and device ("10de", "2504") up in a pci.ids
// database and returns "Vendor Device", or "" when not found.
func pciName(r io.Reader, vendor, device string) string {
	vendor, device = strings.ToLower(vendor), strings.ToLower(device)
	sc := bufio.NewScanner(io.LimitReader(r, 8<<20))
	sc.Buffer(make([]byte, 4096), 4096)
	vname := ""
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] != '\t' {
			if vname != "" || strings.HasPrefix(line, "C ") {
				break // past our vendor, or into the class list
			}
			if id, name, ok := strings.Cut(line, "  "); ok && id == vendor {
				vname = shortVendor(name)
			}
			continue
		}
		if vname == "" || strings.HasPrefix(line, "\t\t") {
			continue
		}
		if id, name, ok := strings.Cut(line[1:], "  "); ok && id == device {
			name = strings.TrimSpace(name)
			if lb, rb := strings.IndexByte(name, '['), strings.LastIndexByte(name, ']'); lb >= 0 && rb > lb {
				name = name[lb+1 : rb] // marketing name: "GA106 [GeForce RTX 3060]"
			}
			return vname + " " + name
		}
	}
	return ""
}

func shortVendor(name string) string {
	n := strings.TrimSpace(name)
	l := strings.ToLower(n)
	switch {
	case strings.Contains(l, "nvidia"):
		return "NVIDIA"
	case strings.Contains(l, "advanced micro devices"), strings.HasPrefix(l, "ati "):
		return "AMD"
	case strings.HasPrefix(l, "intel"):
		return "Intel"
	}
	return n
}

// parseUtmpUsers counts distinct user names of USER_PROCESS records in a
// 64-bit glibc utmp file (384-byte records). The names are dropped.
func parseUtmpUsers(b []byte) int {
	const recSize, userOff, userLen = 384, 44, 32
	users := map[string]bool{}
	for off := 0; off+recSize <= len(b) && off < recSize*4096; off += recSize {
		if binary.LittleEndian.Uint16(b[off:]) != 7 { // USER_PROCESS
			continue
		}
		u := b[off+userOff : off+userOff+userLen]
		if i := strings.IndexByte(string(u), 0); i >= 0 {
			u = u[:i]
		}
		if len(u) > 0 {
			users[string(u)] = true
		}
	}
	return len(users)
}

// parseSessionFile reads a /run/systemd/sessions file and returns its UID
// when it is an open user session (not a greeter or a closing one).
func parseSessionFile(text string) string {
	uid, class, state := "", "", ""
	for line := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "UID":
			uid = v
		case "CLASS":
			class = v
		case "STATE":
			state = v
		}
	}
	if class != "user" || state == "closing" {
		return ""
	}
	return uid
}

// linuxBattery builds a battery from power_supply attribute values
// (read returns "" for a missing attribute).
func linuxBattery(read func(string) string) *Battery {
	num := func(name string) uint64 {
		v, _ := strconv.ParseUint(read(name), 10, 64)
		return v
	}
	b := &Battery{}
	pct, err := strconv.Atoi(read("capacity"))
	if err != nil {
		return nil
	}
	b.Percent = pct
	switch strings.ToLower(read("status")) {
	case "charging":
		b.State = "charging"
	case "discharging":
		b.State = "discharging"
	case "full":
		b.State = "full"
	case "not charging":
		b.State = "ac"
	}
	design, full := num("energy_full_design"), num("energy_full")
	if design > 0 {
		b.DesignMWh, b.FullMWh = design/1000, full/1000 // µWh
	} else if cd, cf := num("charge_full_design"), num("charge_full"); cd > 0 {
		design, full = cd, cf
		if mv := num("voltage_min_design"); mv > 0 { // µAh × µV
			b.DesignMWh, b.FullMWh = cd*mv/1_000_000_000, cf*mv/1_000_000_000
		}
	}
	if design > 0 && full > 0 {
		b.Health = int((full*100 + design/2) / design)
	}
	b.Cycles = int(num("cycle_count"))
	return b
}
