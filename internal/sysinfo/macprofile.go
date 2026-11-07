package sysinfo

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Parsing of macOS "system_profiler -json -detailLevel mini" output. The
// mini level already leaves serial numbers out; the parser additionally
// reads only the keys below, so UUIDs, serials and network names are never
// copied even if a future macOS adds them. It is pure, so it is tested on
// every system.

type macProfile struct {
	gpus     []GPU
	displays []Display
	disks    []Disk
	volumes  []Volume
	battery  *Battery
	modules  []MemModule
	model    string // "MacBook Air"
	modelID  string // "Mac14,2"
	firmware string // boot ROM / system firmware version
	nicTypes map[string]string
}

func parseSystemProfiler(data []byte) macProfile {
	var p macProfile
	p.nicTypes = map[string]string{}
	var root map[string][]map[string]any
	if json.Unmarshal(data, &root) != nil {
		return p
	}
	for _, h := range root["SPHardwareDataType"] {
		p.model, p.modelID = pstr(h["machine_name"]), pstr(h["machine_model"])
		p.firmware = pstr(h["boot_rom_version"])
		if p.firmware == "" {
			p.firmware = pstr(h["system_firmware_version"])
		}
	}
	for _, g := range root["SPDisplaysDataType"] {
		gpu := GPU{Model: pstr(g["sppci_model"])}
		if gpu.Model == "" {
			gpu.Model = pstr(g["_name"])
		}
		for _, k := range []string{"spdisplays_vram", "_spdisplays_vram", "spdisplays_vram_shared"} {
			if v := sizeString(pstr(g[k])); v > 0 {
				gpu.VRAM = v
				break
			}
		}
		p.gpus = append(p.gpus, gpu)
		drvs, _ := g["spdisplays_ndrvs"].([]any)
		for _, x := range drvs {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			disp := Display{Name: pstr(m["_name"])}
			disp.W, disp.H, _ = resolution(pstr(m["_spdisplays_pixels"]))
			rw, rh, hz := resolution(pstr(m["_spdisplays_resolution"]))
			if disp.W == 0 {
				disp.W, disp.H = rw, rh
			}
			disp.Hz = hz
			if disp.W > 0 && disp.H > 0 {
				p.displays = append(p.displays, disp)
			}
		}
	}
	diskIdx := map[string]int{}
	for _, v := range root["SPStorageDataType"] {
		vol := Volume{Mount: MaskMount(pstr(v["mount_point"])), FS: pstr(v["file_system"]), Disk: -1}
		vol.Size, vol.Free = pnum(v["size_in_bytes"]), pnum(v["free_space_in_bytes"])
		if pd, ok := v["physical_drive"].(map[string]any); ok {
			name := pstr(pd["device_name"])
			proto := strings.ToLower(pstr(pd["protocol"]))
			key := name + "/" + proto
			i, ok := diskIdx[key]
			if !ok {
				k := Disk{Index: len(p.disks), Model: name, Removable: pstr(pd["is_internal_disk"]) == "no"}
				switch {
				case strings.Contains(proto, "nvme") || proto == "apple fabric" || proto == "pci-express":
					k.Bus, k.Type = "nvme", "nvme"
				case strings.Contains(proto, "usb"):
					k.Bus = "usb"
				case strings.Contains(proto, "sata"):
					k.Bus = "sata"
				case strings.Contains(proto, "thunderbolt"):
					k.Bus = "other"
				}
				if k.Type == "" {
					switch pstr(pd["medium_type"]) {
					case "ssd":
						k.Type = "ssd"
					case "rotational":
						k.Type = "hdd"
					}
				}
				i = k.Index
				diskIdx[key] = i
				p.disks = append(p.disks, k)
			}
			vol.Disk, vol.Removable = i, p.disks[i].Removable
		}
		if vol.Mount != "" {
			p.volumes = append(p.volumes, vol)
		}
	}
	for _, b := range root["SPPowerDataType"] {
		if pstr(b["_name"]) != "spbattery_information" {
			continue
		}
		bat := &Battery{}
		charge, _ := b["sppower_battery_charge_info"].(map[string]any)
		health, _ := b["sppower_battery_health_info"].(map[string]any)
		bat.Percent = int(pnum(charge["sppower_battery_state_of_charge"]))
		switch {
		case strings.EqualFold(pstr(charge["sppower_battery_is_charging"]), "true"):
			bat.State = "charging"
		case strings.EqualFold(pstr(charge["sppower_battery_fully_charged"]), "true"):
			bat.State = "full"
		default:
			bat.State = "discharging"
		}
		bat.Cycles = int(pnum(health["sppower_battery_cycle_count"]))
		bat.Health = int(pnum(strings.TrimSuffix(pstr(health["sppower_battery_health_maximum_capacity"]), "%")))
		p.battery = bat
	}
	for _, m := range root["SPMemoryDataType"] {
		if items, ok := m["_items"].([]any); ok {
			for _, x := range items {
				it, ok := x.(map[string]any)
				if !ok {
					continue
				}
				size := sizeString(pstr(it["dimm_size"]))
				if size == 0 {
					continue
				}
				speed, _ := strconv.Atoi(strings.Fields(pstr(it["dimm_speed"]) + " 0")[0])
				p.modules = append(p.modules, MemModule{Size: size, Type: pstr(it["dimm_type"]), MHz: speed})
			}
			continue
		}
		if size := sizeString(pstr(m["SPMemoryDataType"])); size > 0 {
			p.modules = append(p.modules, MemModule{Size: size, Type: pstr(m["dimm_type"])})
		}
	}
	for _, n := range root["SPNetworkDataType"] {
		ifname := pstr(n["interface"])
		switch t := strings.ToLower(pstr(n["type"])); {
		case ifname == "":
		case t == "airport" || t == "wi-fi":
			p.nicTypes[ifname] = "wifi"
		case t == "ethernet":
			p.nicTypes[ifname] = "ethernet"
		case strings.Contains(t, "bluetooth"):
			p.nicTypes[ifname] = "bluetooth"
		case t == "ppp" || t == "vpn" || t == "bridge":
			p.nicTypes[ifname] = "virtual"
		default:
			p.nicTypes[ifname] = "other"
		}
	}
	return p
}

func pstr(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func pnum(v any) uint64 {
	switch x := v.(type) {
	case float64:
		if x > 0 && x < 1<<62 {
			return uint64(x)
		}
	case string:
		n, _ := strconv.ParseUint(strings.TrimSpace(x), 10, 64)
		return n
	}
	return 0
}

// sizeString parses "16 GB", "1536 MB" or "512 GB" (binary units, as
// system_profiler means them).
func sizeString(s string) uint64 {
	f := strings.Fields(strings.ReplaceAll(s, ",", "."))
	if len(f) != 2 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v <= 0 {
		return 0
	}
	mult := map[string]float64{"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}[strings.ToUpper(f[1])]
	return uint64(v * mult)
}

// resolution parses "2940 x 1912" or "1470 x 956 @ 60.00Hz".
func resolution(s string) (w, h, hz int) {
	res, rate, _ := strings.Cut(s, "@")
	f := strings.Fields(strings.ReplaceAll(res, "x", " "))
	if len(f) >= 2 {
		w, _ = strconv.Atoi(f[0])
		h, _ = strconv.Atoi(f[1])
	}
	if r, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(rate), "Hz"), 64); err == nil {
		hz = int(r + 0.5)
	}
	return w, h, hz
}
