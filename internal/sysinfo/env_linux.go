//go:build linux

package sysinfo

import (
	"os"
	"path/filepath"
	"strings"
)

func readSmall(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	return strings.TrimSpace(strings.TrimRight(string(buf[:n]), "\x00"))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func collectEnv(in *Info) {
	vendor := readSmall("/sys/class/dmi/id/sys_vendor")
	product := readSmall("/sys/class/dmi/id/product_name")
	in.Model = joinModel(vendor, product)
	if in.Model == "" {
		// Single-board computers (Raspberry Pi and others).
		in.Model = readSmall("/proc/device-tree/model")
	}
	in.Virt = linuxVirt(vendor, product)
	in.Pkg = linuxPackage(in.Virt)
}

func linuxVirt(vendor, product string) string {
	switch {
	case exists("/.dockerenv"):
		return "docker"
	case exists("/run/.containerenv"):
		return "podman"
	}
	cg := readSmall("/proc/1/cgroup")
	switch {
	case strings.Contains(cg, "kubepods"):
		return "kubernetes"
	case strings.Contains(cg, "docker"):
		return "docker"
	case strings.Contains(cg, "lxc"):
		return "lxc"
	}
	if strings.Contains(strings.ToLower(readSmall("/proc/sys/kernel/osrelease")), "microsoft") {
		return "wsl"
	}
	if v := virtFromModel(vendor, product); v != "" {
		return v
	}
	if strings.Contains(readSmall("/proc/cpuinfo"), " hypervisor") {
		return "vm"
	}
	return ""
}

// linuxPackage guesses how this program was installed from where it runs.
func linuxPackage(virt string) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	switch {
	case strings.HasPrefix(exe, "/nix/store/"):
		return "nix"
	case strings.HasPrefix(exe, "/snap/"):
		return "snap"
	case exists("/var/lib/dpkg/info/openscale.list"):
		return "deb"
	case strings.HasPrefix(exe, "/usr/bin/") || strings.HasPrefix(exe, "/usr/sbin/"):
		if exists("/var/lib/rpm") || exists("/usr/lib/sysimage/rpm") {
			return "rpm"
		}
		return "system"
	case virt == "docker" || virt == "podman" || virt == "kubernetes":
		return "container"
	}
	return "tar"
}
