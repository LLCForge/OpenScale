package posture

import (
	"bufio"
	"io"
	"io/fs"
	"strings"
)

// Pure parsers shared by the platform checks; they are tested on every
// system with in-memory inputs.

const maxSysFile = 64 << 10

func readSmall(fsys fs.FS, name string) (string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSysFile))
	return string(data), err
}

// rootEncrypted finds the block device under "/" in mountinfo and walks
// its device-mapper chain looking for a dm-crypt ("CRYPT-") target. It
// answers Off only when it found a real block device chain without one.
func rootEncrypted(fsys fs.FS) State {
	mi, err := readSmall(fsys, "proc/self/mountinfo")
	if err != nil {
		return Unknown
	}
	devnum := rootDevNumber(mi)
	if devnum == "" || strings.HasPrefix(devnum, "0:") {
		// Major 0: overlay, tmpfs, btrfs subvolume or ZFS; no block chain
		// to inspect, so the answer is unknown rather than "off".
		return Unknown
	}
	name := blockByDevNumber(fsys, devnum)
	if name == "" {
		return Unknown
	}
	if cryptChain(fsys, name, 0) {
		return On
	}
	return Off
}

// rootDevNumber returns the "major:minor" of the last mount of "/".
func rootDevNumber(mountinfo string) string {
	dev := ""
	sc := bufio.NewScanner(strings.NewReader(mountinfo))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 5 && f[4] == "/" {
			dev = f[2]
		}
	}
	return dev
}

func blockByDevNumber(fsys fs.FS, devnum string) string {
	entries, err := fs.ReadDir(fsys, "sys/class/block")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		d, err := readSmall(fsys, "sys/class/block/"+e.Name()+"/dev")
		if err == nil && strings.TrimSpace(d) == devnum {
			return e.Name()
		}
	}
	return ""
}

// cryptChain reports whether name or any device below it (LVM on LUKS,
// RAID on LUKS) is a dm-crypt target.
func cryptChain(fsys fs.FS, name string, depth int) bool {
	if depth > 8 || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return false
	}
	if uuid, err := readSmall(fsys, "sys/class/block/"+name+"/dm/uuid"); err == nil && strings.HasPrefix(strings.TrimSpace(uuid), "CRYPT-") {
		return true
	}
	slaves, err := fs.ReadDir(fsys, "sys/class/block/"+name+"/slaves")
	if err != nil {
		return false
	}
	for _, s := range slaves {
		if cryptChain(fsys, s.Name(), depth+1) {
			return true
		}
	}
	return false
}

// ufwEnabled reads ufw's own on/off switch.
func ufwEnabled(conf string) bool {
	for line := range strings.SplitSeq(conf, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "ENABLED" && strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "yes") {
			return true
		}
	}
	return false
}

// nftInputFiltering reads "nft list ruleset" text: On when a chain hooked
// at input drops by policy or holds a drop/reject statement, Off when the
// ruleset has no such chain.
func nftInputFiltering(ruleset string) State {
	inChain, inputHook, filtering := false, false, false
	depth := 0
	for line := range strings.SplitSeq(ruleset, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "chain ") && strings.HasSuffix(t, "{") {
			inChain, inputHook, filtering = true, false, false
			depth = 0
		}
		if inChain {
			if strings.Contains(t, "hook input") {
				inputHook = true
			}
			if strings.Contains(t, "policy drop") || t == "drop" || strings.HasSuffix(t, " drop") || strings.Contains(t, " reject") || strings.HasPrefix(t, "reject") {
				filtering = true
			}
			depth += strings.Count(t, "{") - strings.Count(t, "}")
			if depth <= 0 {
				if inputHook && filtering {
					return On
				}
				inChain = false
			}
		}
	}
	return Off
}

// windowsFirewall combines the three profile switches (domain, private,
// public). A group policy value, when set, wins over the local one. Any
// profile explicitly off is Off; all on is On; anything unreadable is
// Unknown.
func windowsFirewall(policy, local [3]int) State {
	all := On
	for i := range 3 {
		v := local[i]
		if policy[i] >= 0 {
			v = policy[i]
		}
		switch {
		case v == 0:
			return Off
		case v < 0:
			all = Unknown
		}
	}
	return all
}

// bitlockerFromOutput maps Win32_EncryptableVolume.ProtectionStatus
// (0 off, 1 on, 2 unknown) printed by PowerShell.
func bitlockerFromOutput(out string) State {
	switch strings.TrimSpace(out) {
	case "1":
		return On
	case "0":
		return Off
	}
	return Unknown
}

// bitlockerVolumesFromOutput parses "C:=1" lines (drive letter and
// Win32_EncryptableVolume.ProtectionStatus) printed by PowerShell.
// Volumes without a drive letter and malformed lines are skipped.
func bitlockerVolumesFromOutput(out string) map[string]State {
	m := map[string]State{}
	for line := range strings.SplitSeq(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		k = strings.ToUpper(strings.TrimSpace(k))
		if !ok || len(k) != 2 || k[1] != ':' || k[0] < 'A' || k[0] > 'Z' || len(m) >= 26 {
			continue
		}
		m[k] = bitlockerFromOutput(v)
	}
	return m
}

// DeviceEncryptedIn reports whether the block device numbered devnum
// ("major:minor") or a device below it is a dm-crypt target, reading
// sysfs from fsys. Unknown when the device is not found.
func DeviceEncryptedIn(fsys fs.FS, devnum string) State {
	if devnum == "" || strings.HasPrefix(devnum, "0:") {
		return Unknown
	}
	name := blockByDevNumber(fsys, devnum)
	if name == "" {
		return Unknown
	}
	if cryptChain(fsys, name, 0) {
		return On
	}
	return Off
}
