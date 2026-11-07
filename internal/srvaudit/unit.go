package srvaudit

import (
	"io/fs"
	"slices"
	"strings"
)

// unitDirs are searched in systemd's order of precedence.
var unitDirs = []string{"etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"}

// unitSettings reads a unit and its drop-ins: the last assignment of a key
// wins and an empty assignment clears it, as in systemd.
func unitSettings(fsys fs.FS, name string) (map[string]string, string, bool) {
	var main, where string
	for _, d := range unitDirs {
		if data, err := readSmall(fsys, d+"/"+name); err == nil {
			main, where = data, d+"/"+name
			break
		}
	}
	if where == "" {
		return nil, "", false
	}
	vals := map[string]string{}
	parseUnit(main, vals)
	var dropins []string
	for _, d := range unitDirs {
		entries, err := fs.ReadDir(fsys, d+"/"+name+".d")
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") && !slices.ContainsFunc(dropins, func(p string) bool { return strings.HasSuffix(p, "/"+e.Name()) }) {
				dropins = append(dropins, d+"/"+name+".d/"+e.Name())
			}
		}
	}
	slices.SortFunc(dropins, func(a, b string) int {
		return strings.Compare(a[strings.LastIndexByte(a, '/'):], b[strings.LastIndexByte(b, '/'):])
	})
	for _, p := range dropins {
		if data, err := readSmall(fsys, p); err == nil {
			parseUnit(data, vals)
		}
	}
	return vals, where, true
}

// parseUnit adds the [Service] assignments of text to vals. Multi-value
// keys keep their last non-empty assignment, which is enough to tell
// whether a setting is present.
func parseUnit(text string, vals map[string]string) {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		if section != "Service" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if v == "" {
			delete(vals, k)
			continue
		}
		vals[k] = v
	}
}

// unitRequirement is one hardening setting the shipped unit has.
type unitRequirement struct {
	key  string
	ok   func(string) bool
	hint string
}

func isYes(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

func present(string) bool { return true }

func coordinatorRequirements() []unitRequirement {
	return []unitRequirement{
		{"User", func(v string) bool { return v != "" && v != "root" && v != "0" }, "User=openscale"},
		{"NoNewPrivileges", isYes, "NoNewPrivileges=yes"},
		{"ProtectSystem", func(v string) bool { return v == "strict" }, "ProtectSystem=strict"},
		{"ProtectHome", isYes, "ProtectHome=yes"},
		{"PrivateDevices", isYes, "PrivateDevices=yes"},
		{"CapabilityBoundingSet", func(v string) bool { return v == "CAP_NET_BIND_SERVICE" || v == "" }, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"},
		{"SystemCallFilter", present, "SystemCallFilter=@system-service"},
		{"RestrictAddressFamilies", present, "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK"},
		{"MemoryMax", present, "MemoryMax=512M (#484)"},
		{"TasksMax", present, "TasksMax=256 (#484)"},
		{"LimitNOFILE", present, "LimitNOFILE=4096"},
	}
}

func exitRequirements() []unitRequirement {
	return []unitRequirement{
		{"NoNewPrivileges", isYes, "NoNewPrivileges=yes"},
		{"ProtectSystem", func(v string) bool { return v == "strict" }, "ProtectSystem=strict"},
		{"ProtectHome", isYes, "ProtectHome=yes"},
		{"CapabilityBoundingSet", func(v string) bool {
			for _, f := range strings.Fields(v) {
				if f != "CAP_NET_ADMIN" && f != "CAP_NET_RAW" && f != "CAP_NET_BIND_SERVICE" {
					return false
				}
			}
			return true
		}, "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW"},
		{"SystemCallFilter", present, "SystemCallFilter=@system-service"},
	}
}

func checkUnit(fsys fs.FS, role string) Check {
	name, reqs := "openscale-coordinator.service", coordinatorRequirements()
	if role == RoleExit {
		name, reqs = "openscale-device.service", exitRequirements()
	}
	c := Check{ID: "unit", Title: "OpenScale birim sertleştirmesi", Weight: 10}
	vals, where, ok := unitSettings(fsys, name)
	if !ok {
		c.Status, c.Detail = Fail, name+" bulunamadı."
		c.Fix = "openscale service install --role " + map[bool]string{true: "device", false: "coordinator"}[role == RoleExit]
		return c
	}
	var missing []string
	for _, r := range reqs {
		v, set := vals[r.key]
		if !set || !r.ok(v) {
			missing = append(missing, r.hint)
		}
	}
	switch {
	case len(missing) == 0:
		c.Status, c.Detail = Pass, where+" sertleştirilmiş."
	case len(missing) <= 2:
		c.Status = Warn
	default:
		c.Status = Fail
	}
	if len(missing) > 0 {
		c.Detail = where + " içinde eksik veya zayıf: " + strings.Join(missing, ", ")
		c.Fix = "Dağıtımdaki birimi (deploy/linux) kullanın; yerel drop-in'lerin bu ayarları gevşetmediğini denetleyin."
	}
	return c
}
