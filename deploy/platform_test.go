// Package deploy holds the tests of the platform packaging files of Faz 6B
// (#884-#891): immutable Linux, AppArmor/SELinux, pfSense/OPNsense,
// RouterOS, Home Assistant OS and Qubes OS. None of them can be run here,
// so the tests parse every file, run the shell syntax checker and assert
// the security-relevant settings (least privilege, fail-closed kill
// switch, no download, no outside address). Nothing here is shipped.
package deploy

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

func read(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// shellScripts are checked with "sh -n"; bashScripts with "bash -n".
var shellScripts = []string{
	"linux/immutable/install-immutable.sh",
	"linux/immutable/openscale-repair.sh",
	"linux/apparmor/install-apparmor.sh",
	"linux/apparmor/uninstall-apparmor.sh",
	"linux/selinux/install-selinux.sh",
	"linux/selinux/uninstall-selinux.sh",
	"pfsense/openscale.rc",
	"pfsense/build-pkg.sh",
	"opnsense/build-plugin.sh",
	"routeros/routeros-entrypoint.sh",
	"homeassistant/prepare.sh",
	"qubes/dom0-create-sys-openscale.sh",
	"qubes/qube-setup.sh",
	"qubes/qubes-firewall-user-script",
	"qubes/rc.local",
}

var bashScripts = []string{"homeassistant/openscale/run.sh", "qubes/50_openscale.conf"}

// shellPath finds a POSIX shell. On Windows "bash" may be the WSL
// launcher, so Git's sh is preferred.
func shellPath(t *testing.T, names ...string) string {
	t.Helper()
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			if strings.Contains(strings.ToLower(p), `\windows\system32\`) {
				continue
			}
			return p
		}
	}
	t.Skipf("%v yok", names)
	return ""
}

func TestShellSyntax(t *testing.T) {
	sh := shellPath(t, "sh", "dash", "bash")
	for _, f := range shellScripts {
		if out, err := exec.Command(sh, "-n", filepath.FromSlash(f)).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", f, err, out)
		}
		s := read(t, f)
		if !strings.HasPrefix(s, "#!/bin/sh\n") {
			t.Errorf("%s: #!/bin/sh ile başlamalı", f)
		}
		if strings.Contains(s, "\r") {
			t.Errorf("%s: CRLF satır sonu", f)
		}
		// No download, no pipe into a shell (ADR-0022: nothing unverified runs).
		for _, bad := range []string{"curl ", "wget ", "fetch ", "| sh", "|sh", "eval "} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: %q içeriyor", f, bad)
			}
		}
	}
	bash := shellPath(t, "bash")
	for _, f := range bashScripts {
		if out, err := exec.Command(bash, "-n", filepath.FromSlash(f)).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", f, err, out)
		}
	}
}

// ---- A YAML subset parser (block maps, block lists, flow lists, quoted
// and plain scalars). The files are written within this subset so that a
// stricter check than "looks like YAML" is possible without a dependency.

type yline struct {
	n      int
	indent int
	text   string
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '#' && !inS && !inD && (i == 0 || s[i-1] == ' '):
			return strings.TrimRight(s[:i], " ")
		}
	}
	return strings.TrimRight(s, " ")
}

func parseYAML(src string) (any, error) {
	var lines []yline
	for i, raw := range strings.Split(src, "\n") {
		if strings.Contains(raw, "\t") {
			return nil, fmt.Errorf("satır %d: sekme", i+1)
		}
		s := stripComment(raw)
		if strings.TrimSpace(s) == "" {
			continue
		}
		ind := len(s) - len(strings.TrimLeft(s, " "))
		lines = append(lines, yline{i + 1, ind, strings.TrimSpace(s)})
	}
	if len(lines) == 0 {
		return nil, errors.New("boş belge")
	}
	v, next, err := parseNode(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next != len(lines) {
		return nil, fmt.Errorf("satır %d: beklenmeyen girinti", lines[next].n)
	}
	return v, nil
}

func parseNode(ls []yline, i, indent int) (any, int, error) {
	if strings.HasPrefix(ls[i].text, "- ") || ls[i].text == "-" {
		var out []any
		for i < len(ls) && ls[i].indent == indent && (strings.HasPrefix(ls[i].text, "- ") || ls[i].text == "-") {
			item := strings.TrimSpace(strings.TrimPrefix(ls[i].text, "-"))
			if item == "" {
				if i+1 >= len(ls) || ls[i+1].indent <= indent {
					return nil, 0, fmt.Errorf("satır %d: boş liste öğesi", ls[i].n)
				}
				v, next, err := parseNode(ls, i+1, ls[i+1].indent)
				if err != nil {
					return nil, 0, err
				}
				out = append(out, v)
				i = next
				continue
			}
			if _, _, ok := splitKey(item); ok {
				return nil, 0, fmt.Errorf("satır %d: liste içinde eşleme bu alt kümede yok", ls[i].n)
			}
			v, err := scalar(item, ls[i].n)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, v)
			i++
		}
		return out, i, nil
	}
	out := map[string]any{}
	for i < len(ls) && ls[i].indent == indent {
		k, rest, ok := splitKey(ls[i].text)
		if !ok {
			return nil, 0, fmt.Errorf("satır %d: 'anahtar: değer' bekleniyor: %q", ls[i].n, ls[i].text)
		}
		if _, dup := out[k]; dup {
			return nil, 0, fmt.Errorf("satır %d: yinelenen anahtar %q", ls[i].n, k)
		}
		if rest != "" {
			v, err := scalar(rest, ls[i].n)
			if err != nil {
				return nil, 0, err
			}
			out[k] = v
			i++
			continue
		}
		if i+1 < len(ls) && ls[i+1].indent > indent {
			v, next, err := parseNode(ls, i+1, ls[i+1].indent)
			if err != nil {
				return nil, 0, err
			}
			out[k] = v
			i = next
			continue
		}
		// A list may sit at the same indentation as its key.
		if i+1 < len(ls) && ls[i+1].indent == indent && strings.HasPrefix(ls[i+1].text, "- ") {
			v, next, err := parseNode(ls, i+1, indent)
			if err != nil {
				return nil, 0, err
			}
			out[k] = v
			i = next
			continue
		}
		out[k] = ""
		i++
	}
	if i < len(ls) && ls[i].indent > indent {
		return nil, 0, fmt.Errorf("satır %d: beklenmeyen girinti", ls[i].n)
	}
	return out, i, nil
}

// splitKey splits "key: value" or "key:" outside quotes.
func splitKey(s string) (string, string, bool) {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD && i == 0:
			inS = true
		case c == '\'' && inS:
			inS = false
		case c == '"' && !inS && i == 0:
			inD = true
		case c == '"' && inD:
			inD = false
		case c == ':' && !inS && !inD && (i == len(s)-1 || s[i+1] == ' '):
			k := strings.TrimSpace(s[:i])
			if uq, err := unquote(k); err == nil {
				k = uq
			}
			if k == "" {
				return "", "", false
			}
			return k, strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func unquote(s string) (string, error) {
	switch {
	case len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"':
		var out string
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return "", err
		}
		return out, nil
	case len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'':
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	return s, errors.New("tırnaksız")
}

func scalar(s string, n int) (any, error) {
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("satır %d: kapanmayan liste", n)
		}
		var out []any
		for p := range strings.SplitSeq(s[1:len(s)-1], ",") {
			if p = strings.TrimSpace(p); p != "" {
				v, err := scalar(p, n)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
		}
		return out, nil
	}
	if s[0] == '"' || s[0] == '\'' {
		v, err := unquote(s)
		if err != nil {
			return nil, fmt.Errorf("satır %d: tırnak: %v", n, err)
		}
		return v, nil
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "&") || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "|") || strings.HasPrefix(s, ">") {
		return nil, fmt.Errorf("satır %d: bu alt kümede olmayan yapı: %q", n, s)
	}
	// In real YAML these make a plain scalar ambiguous or invalid.
	if strings.Contains(s, ": ") || strings.HasPrefix(s, "@") || strings.HasPrefix(s, "`") {
		return nil, fmt.Errorf("satır %d: düz değer tırnak istiyor: %q", n, s)
	}
	return s, nil
}

func yamlFile(t *testing.T, rel string) map[string]any {
	t.Helper()
	v, err := parseYAML(read(t, rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: üst düzey eşleme değil", rel)
	}
	return m
}

func strList(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func keys(v any) []string {
	m, _ := v.(map[string]any)
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestYAMLSubsetParser(t *testing.T) {
	v, err := parseYAML("a: 1\nb:\n  - x\n  - 'y z'\nc:\n  d: \"e: f\" # yorum\nl: [p, q]\n")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["a"] != "1" || !slices.Equal(strList(m["b"]), []string{"x", "y z"}) || m["c"].(map[string]any)["d"] != "e: f" || !slices.Equal(strList(m["l"]), []string{"p", "q"}) {
		t.Errorf("%#v", m)
	}
	for _, bad := range []string{"a: 1\na: 2\n", "a: b: c\n", "a:\n\t- x\n", "a: 1\n   b: 2\n", "a: {x: 1}\n", "- k: v\n"} {
		if _, err := parseYAML(bad); err == nil {
			t.Errorf("kabul edildi: %q", bad)
		}
	}
}

// ---- Home Assistant (#890)

func TestHomeAssistantAddon(t *testing.T) {
	repo := yamlFile(t, "homeassistant/repository.yaml")
	for _, k := range []string{"name", "url", "maintainer"} {
		if s, _ := repo[k].(string); s == "" {
			t.Errorf("repository.yaml: %s yok", k)
		}
	}
	c := yamlFile(t, "homeassistant/openscale/config.yaml")
	for _, k := range []string{"name", "version", "slug", "description", "arch"} {
		if c[k] == nil {
			t.Errorf("config.yaml: %s yok", k)
		}
	}
	if c["slug"] != "openscale" || !regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-z]+\.\d+)?$`).MatchString(c["version"].(string)) {
		t.Errorf("slug/version: %v %v", c["slug"], c["version"])
	}
	// Least privilege: exactly NET_ADMIN and the TUN device.
	if got := strList(c["privileged"]); !slices.Equal(got, []string{"NET_ADMIN"}) {
		t.Errorf("privileged = %v, yalnızca NET_ADMIN olmalı", got)
	}
	if got := strList(c["devices"]); !slices.Equal(got, []string{"/dev/net/tun"}) {
		t.Errorf("devices = %v", got)
	}
	for _, k := range []string{"full_access", "docker_api", "host_pid", "host_ipc", "host_dbus", "hassio_api", "hassio_role", "homeassistant_api", "auth_api", "kernel_modules", "udev", "usb", "uart", "gpio", "video", "audio", "map", "ingress", "ports"} {
		if _, ok := c[k]; ok {
			t.Errorf("config.yaml: gereksiz yetki %q", k)
		}
	}
	if c["apparmor"] != "true" || c["host_network"] != "true" || c["init"] != "false" {
		t.Errorf("apparmor/host_network/init: %v %v %v", c["apparmor"], c["host_network"], c["init"])
	}
	if got := strList(c["services"]); !slices.Equal(got, []string{"mqtt:want"}) {
		t.Errorf("services = %v (MQTT zorunlu olmamalı)", got)
	}
	arch := strList(c["arch"])
	for _, a := range arch {
		if !slices.Contains([]string{"aarch64", "amd64", "armv7"}, a) {
			t.Errorf("mimari %q yayımlanmıyor", a)
		}
	}
	build := yamlFile(t, "homeassistant/openscale/build.yaml")
	if got := keys(build["build_from"]); !slices.Equal(got, sortedCopy(arch)) {
		t.Errorf("build_from %v != arch %v", got, arch)
	}
	schema := keys(c["schema"])
	for _, k := range keys(c["options"]) {
		if !slices.Contains(schema, k) {
			t.Errorf("options.%s şemada yok", k)
		}
	}
	if sch := c["schema"].(map[string]any); sch["invite_code"] != "password?" {
		t.Errorf("invite_code parola türünde ve isteğe bağlı olmalı: %v", sch["invite_code"])
	}
	for _, lang := range []string{"en", "tr"} {
		tr := yamlFile(t, "homeassistant/openscale/translations/"+lang+".yaml")
		if got := keys(tr["configuration"]); !slices.Equal(got, schema) {
			t.Errorf("%s çevirisi %v, şema %v", lang, got, schema)
		}
		for k, v := range tr["configuration"].(map[string]any) {
			e, _ := v.(map[string]any)
			if n, _ := e["name"].(string); n == "" {
				t.Errorf("%s.%s: name yok", lang, k)
			}
			if d, _ := e["description"].(string); d == "" {
				t.Errorf("%s.%s: description yok", lang, k)
			}
		}
	}
	df := read(t, "homeassistant/openscale/Dockerfile")
	if !strings.Contains(df, "COPY bin/openscale-${BUILD_ARCH} /usr/bin/openscale") || regexp.MustCompile(`(?i)curl|wget|ADD\s+http`).MatchString(df) {
		t.Errorf("Dockerfile programı bin/'den kopyalamalı, indirmemeli")
	}
	run := read(t, "homeassistant/openscale/run.sh")
	if !strings.HasPrefix(run, "#!/usr/bin/with-contenv bashio\n") || !strings.Contains(run, `--code "@$invite"`) || strings.Contains(run, "set -x") {
		t.Errorf("run.sh: davet dosyayla verilmeli, set -x olmamalı")
	}
	if strings.Contains(run, "--password ") {
		t.Errorf("run.sh: MQTT parolası komut satırına yazılmamalı")
	}
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

// ---- RouterOS (#889)

func TestRouterOS(t *testing.T) {
	df := read(t, "routeros/Dockerfile")
	for _, want := range []string{"apk add --no-cache iproute2 nftables", "COPY ${DIST}/openscale-linux-${TARGETARCH}${TARGETVARIANT} /usr/bin/openscale", `ENTRYPOINT ["/usr/local/bin/openscale-routeros"]`, "deploy/docker/entrypoint.sh"} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile: %q yok", want)
		}
	}
	for _, line := range strings.Split(df, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if regexp.MustCompile(`(?i)\b(curl|wget)\b|ADD\s+https?:|--privileged|^USER\b`).MatchString(line) {
			t.Errorf("Dockerfile: %q", line)
		}
	}
	ign := read(t, "routeros/Dockerfile.dockerignore")
	if !strings.HasPrefix(stripHashLines(ign), "*\n") {
		t.Errorf("dockerignore izin listesi '*' ile başlamalı")
	}
	rsc := read(t, "routeros/openscale.rsc")
	var cmds []string
	for _, line := range strings.Split(rsc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			t.Errorf("rsc: komut / ile başlamalı: %q", line)
		}
		cmds = append(cmds, line)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"/interface/veth/add", "/interface/bridge/add", "/interface/bridge/port/add", "/container/mounts/add", "/container/envs/add", "/container/add", "/container/start"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rsc: %s yok", want)
		}
	}
	if strings.Contains(strings.ToLower(rsc), "privileged") {
		t.Errorf("rsc: ayrıcalıklı kip istenmemeli")
	}
	ep := read(t, "routeros/routeros-entrypoint.sh")
	if !strings.Contains(ep, "exec /usr/local/bin/openscale-entrypoint") || !strings.Contains(ep, "delete table ip openscale_routeros") {
		t.Errorf("routeros-entrypoint.sh: ortak giriş betiğine geçmeli ve yalnızca kendi tablosunu yenilemeli")
	}
}

func stripHashLines(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "#") && l != "" {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// ---- AppArmor (#886)

var aaCap = regexp.MustCompile(`^\s*capability\s+([a-z_]+)\s*,`)

func apparmorProfile(t *testing.T, name string) (string, []string) {
	t.Helper()
	s := read(t, "linux/apparmor/"+name)
	if strings.Count(s, "{") != strings.Count(s, "}") {
		t.Errorf("%s: süslü parantezler dengesiz", name)
	}
	if !strings.Contains(s, "profile "+name+" flags=(complain) {") {
		t.Errorf("%s: complain kipinde, yol eki olmadan tanımlanmalı", name)
	}
	if !strings.Contains(s, "include if exists <local/"+name+">") {
		t.Errorf("%s: yerel ekleme dosyası yok", name)
	}
	var caps []string
	inBody := false
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "profile ") {
			inBody = true
			continue
		}
		if !inBody || l == "" || strings.HasPrefix(l, "#") || l == "}" || strings.HasPrefix(l, "include") {
			continue
		}
		if !strings.HasSuffix(l, ",") {
			t.Errorf("%s: kural ',' ile bitmeli: %q", name, l)
		}
		if m := aaCap.FindStringSubmatch(l); m != nil {
			caps = append(caps, m[1])
		}
		// Blanket access is never allowed.
		if regexp.MustCompile(`^(/\*\*|/\{?\*|@\{HOME\}|/home/)\S*\s+\S*w`).MatchString(l) || strings.Contains(l, " ux,") || strings.Contains(l, " Ux,") || strings.Contains(l, " pux,") {
			t.Errorf("%s: geniş izin: %q", name, l)
		}
	}
	sort.Strings(caps)
	return s, caps
}

func TestAppArmorProfiles(t *testing.T) {
	dev, caps := apparmorProfile(t, "openscale-device")
	if want := []string{"net_admin", "net_raw", "setgid", "setuid"}; !slices.Equal(caps, want) {
		t.Errorf("cihaz yetenekleri %v, beklenen %v", caps, want)
	}
	for _, want := range []string{"/dev/net/tun rw,", "/var/lib/openscale/device/** rwkl,", "deny /var/lib/openscale/coordinator/** rwklx,", "/run/systemd/notify w,"} {
		if !strings.Contains(dev, want) {
			t.Errorf("cihaz profili: %q yok", want)
		}
	}
	// Every tool the Linux code runs must be in the profile.
	for _, tool := range linuxTools(t) {
		if !regexp.MustCompile(`/\{usr/,\}\{s,\}bin/` + regexp.QuoteMeta(tool) + ` ix,`).MatchString(dev) {
			t.Errorf("cihaz profili %q aracını çalıştıramıyor", tool)
		}
	}
	coord, caps := apparmorProfile(t, "openscale-coordinator")
	if !slices.Equal(caps, []string{"net_bind_service"}) {
		t.Errorf("koordinatör yetenekleri %v", caps)
	}
	for _, line := range strings.Split(coord, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "deny") {
			continue
		}
		if regexp.MustCompile(`\s[mr]*[iPpCcUu]x,$`).MatchString(l) || strings.Contains(l, "/dev/net/tun") {
			t.Errorf("koordinatör program çalıştırmamalı / aygıt açmamalı: %q", l)
		}
	}
	for _, p := range []string{"openscale-device", "openscale-coordinator"} {
		u := parseUnit(t, "linux/apparmor/"+p+"-apparmor.conf")
		if got := u["Service.AppArmorProfile"]; !slices.Equal(got, []string{p}) {
			t.Errorf("%s: AppArmorProfile=%v", p, got)
		}
	}
	inst := read(t, "linux/apparmor/install-apparmor.sh")
	if !strings.Contains(inst, "MODE=complain") || !strings.Contains(inst, "apparmor_parser -Q -K") {
		t.Errorf("install-apparmor.sh: varsayılan complain ve önce ayrıştırma olmalı")
	}
	// Profile loaded before the drop-in; drop-in removed before the profile.
	if strings.Index(inst, "apparmor_parser -r") > strings.Index(inst, "60-openscale-apparmor.conf\"") {
		t.Errorf("install-apparmor.sh: profil ek dosyadan önce yüklenmeli")
	}
	un := read(t, "linux/apparmor/uninstall-apparmor.sh")
	if strings.Index(un, "60-openscale-apparmor.conf") > strings.Index(un, "apparmor_parser -R") {
		t.Errorf("uninstall-apparmor.sh: ek dosya profilden önce kaldırılmalı")
	}
}

// linuxTools are the programs internal/osnet and internal/service run on
// Linux, read from the code so the profile follows it.
func linuxTools(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pat := range []string{"../internal/osnet/*_linux.go", "../internal/service/*_linux.go", "../internal/service/*_unix.go"} {
		m, _ := filepath.Glob(filepath.FromSlash(pat))
		files = append(files, m...)
	}
	re := regexp.MustCompile(`\b(?:run|runForBundle)\(ctx, [A-Za-z_]+, "([a-z][a-z0-9-]*)"|\.has\("([a-z][a-z0-9-]*)"\)`)
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			seen[m[1]+m[2]] = true
		}
	}
	if !seen["ip"] || !seen["nft"] {
		t.Fatalf("araç listesi okunamadı: %v", seen)
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parseUnit reads a systemd unit or drop-in into "Section.Key" -> values.
func parseUnit(t *testing.T, rel string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	sec := ""
	for i, line := range strings.Split(read(t, rel), "\n") {
		l := strings.TrimSpace(line)
		switch {
		case l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";"):
		case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
			sec = l[1 : len(l)-1]
		default:
			k, v, ok := strings.Cut(l, "=")
			if !ok || sec == "" {
				t.Errorf("%s:%d: %q", rel, i+1, l)
				continue
			}
			out[sec+"."+k] = append(out[sec+"."+k], v)
		}
	}
	return out
}

// ---- SELinux (#886)

var seCaps = regexp.MustCompile(`allow (openscale_\w+_t) self:capability \{?\s*([a-z_ ]+?)\s*\}?;`)

func TestSELinuxPolicy(t *testing.T) {
	te := read(t, "linux/selinux/openscale.te")
	if !strings.HasPrefix(te, "policy_module(openscale, ") {
		t.Errorf("openscale.te policy_module ile başlamalı")
	}
	var code strings.Builder
	for _, l := range strings.Split(te, "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		code.WriteString(l + "\n")
	}
	c := code.String()
	// m4 quoting must balance outside comments.
	if strings.Count(c, "`") != strings.Count(c, "'") {
		t.Errorf("openscale.te: m4 tırnakları dengesiz (%d ` / %d ')", strings.Count(c, "`"), strings.Count(c, "'"))
	}
	if strings.Count(c, "(") != strings.Count(c, ")") || strings.Count(c, "{") != strings.Count(c, "}") {
		t.Errorf("openscale.te: parantezler dengesiz")
	}
	// Permissive comes from the installer, never from the shipped file.
	for _, bad := range []string{"permissive ", "unconfined", " *:", "~{", "self:capability *"} {
		if strings.Contains(c, bad) {
			t.Errorf("openscale.te: %q", bad)
		}
	}
	caps := map[string][]string{}
	for _, m := range seCaps.FindAllStringSubmatch(c, -1) {
		caps[m[1]] = append(caps[m[1]], strings.Fields(m[2])...)
	}
	for d, want := range map[string][]string{
		"openscale_device_t":      {"net_admin", "net_raw", "setgid", "setuid"},
		"openscale_coordinator_t": {"net_bind_service"},
	} {
		got := sortedCopy(caps[d])
		if !slices.Equal(got, want) {
			t.Errorf("%s yetenekleri %v, beklenen %v", d, got, want)
		}
	}
	if strings.Contains(c, "openscale_coordinator_t tun_tap_device_t") || strings.Contains(c, "corenet_rw_tun_tap_dev(openscale_coordinator_t)") || strings.Contains(c, "corecmd_exec_bin(openscale_coordinator_t)") {
		t.Errorf("koordinatör aygıt açmamalı / program çalıştırmamalı")
	}
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^type (\w+);`).FindAllStringSubmatch(c, -1) {
		declared[m[1]] = true
	}
	fc := read(t, "linux/selinux/openscale.fc")
	n := 0
	for _, l := range strings.Split(fc, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		m := regexp.MustCompile(`gen_context\(system_u:object_r:(\w+),s0\)$`).FindStringSubmatch(strings.TrimSpace(l))
		if m == nil || !declared[m[1]] {
			t.Errorf("openscale.fc: %q", l)
		}
		n++
	}
	if n < 6 {
		t.Errorf("openscale.fc: %d satır", n)
	}
	inst := read(t, "linux/selinux/install-selinux.sh")
	if !strings.Contains(inst, "MODE=permissive") || !strings.Contains(inst, "permissive openscale_device_t;") || !strings.Contains(inst, "semanage port -a -t openscale_port_t -p udp") {
		t.Errorf("install-selinux.sh: varsayılan permissive, port etiketi")
	}
	u := parseUnit(t, "linux/selinux/openscale-coordinator-selinux.conf")
	if got := u["Service.SELinuxContext"]; !slices.Equal(got, []string{"system_u:system_r:openscale_coordinator_t:s0"}) {
		t.Errorf("SELinuxContext=%v", got)
	}
	un := read(t, "linux/selinux/uninstall-selinux.sh")
	if strings.Index(un, "60-openscale-selinux.conf") > strings.Index(un, "semodule -r") {
		t.Errorf("uninstall-selinux.sh: ek dosya modülden önce kaldırılmalı")
	}
}

// ---- Immutable Linux (#884)

func TestImmutableLinux(t *testing.T) {
	u := parseUnit(t, "linux/immutable/openscale-repair.service")
	if !slices.Equal(u["Service.Type"], []string{"oneshot"}) || !slices.Contains(strings.Fields(strings.Join(u["Unit.Before"], " ")), "openscale-device.service") {
		t.Errorf("onarım birimi oneshot ve cihazdan önce olmalı: %v", u)
	}
	if got := u["Service.ExecStart"]; !slices.Equal(got, []string{"/bin/sh /var/lib/openscale/immutable/openscale-repair.sh --boot"}) {
		t.Errorf("ExecStart=%v", got)
	}
	if !slices.Equal(u["Install.WantedBy"], []string{"multi-user.target"}) || !slices.Equal(u["Unit.ConditionPathExists"], []string{"/var/lib/openscale/immutable/install.conf"}) {
		t.Errorf("birim: %v", u)
	}
	inst := read(t, "linux/immutable/install-immutable.sh")
	for _, want := range []string{"openscale-repair.sh", "openscale-repair.service", "verify \"$BIN\"", "verify \"$LAYER_RPM\"", "rpm-ostree install", "/etc/atomic-update.conf.d", "update auto off"} {
		if !strings.Contains(inst, want) {
			t.Errorf("install-immutable.sh: %q yok", want)
		}
	}
	rep := read(t, "linux/immutable/openscale-repair.sh")
	// The config file is matched, never executed.
	if regexp.MustCompile(`(?m)^\s*(\.|source)\s`).MatchString(rep) || regexp.MustCompile(`(?m)^\s*(\.|source)\s`).MatchString(inst) {
		t.Errorf("install.conf kaynak olarak okunmamalı")
	}
	if !strings.Contains(rep, `[ -s "$2" ] && return 0`) {
		t.Errorf("onarım var olan dosyanın üzerine yazmamalı")
	}
}

// ---- pfSense / OPNsense (#885)

func jsonFile(t *testing.T, rel string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(read(t, rel)), &m); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return m
}

func TestPfSensePackage(t *testing.T) {
	m := jsonFile(t, "pfsense/+MANIFEST")
	for k, want := range map[string]string{"name": "openscale", "origin": "net/openscale", "version": "@VERSION@", "abi": "@ABI@", "arch": "@ARCH@", "prefix": "/usr/local"} {
		if m[k] != want {
			t.Errorf("+MANIFEST %s = %v", k, m[k])
		}
	}
	sc, _ := m["scripts"].(map[string]any)
	for _, k := range []string{"post-install", "pre-deinstall"} {
		if s, _ := sc[k].(string); s == "" {
			t.Errorf("+MANIFEST: %s betiği yok", k)
		}
	}
	plist := strings.Fields(read(t, "pfsense/pkg-plist"))
	if !slices.Equal(plist, []string{"bin/openscale", "etc/rc.d/openscale"}) {
		t.Errorf("pkg-plist %v", plist)
	}
	rc := read(t, "pfsense/openscale.rc")
	for _, want := range []string{". /etc/rc.subr", "rcvar=openscale_enable", `: "${openscale_enable:=NO}"`, "run_rc_command \"$1\"", "# PROVIDE: openscale", "# KEYWORD: shutdown", "anchor.json"} {
		if !strings.Contains(rc, want) {
			t.Errorf("openscale.rc: %q yok", want)
		}
	}
	if !strings.Contains(read(t, "pfsense/build-pkg.sh"), "pkg create -M") {
		t.Errorf("build-pkg.sh pkg create kullanmalı")
	}
}

func TestOPNsensePlugin(t *testing.T) {
	base := "opnsense/src/opnsense/"
	var model struct {
		Mount string `xml:"mount"`
		Items struct {
			General struct {
				Fields []struct {
					XMLName xml.Name
					Type    string `xml:"type,attr"`
					Mask    string `xml:"Mask"`
				} `xml:",any"`
			} `xml:"general"`
		} `xml:"items"`
	}
	if err := xml.Unmarshal([]byte(read(t, base+"mvc/app/models/OPNsense/OpenScale/OpenScale.xml")), &model); err != nil {
		t.Fatal(err)
	}
	if model.Mount != "//OPNsense/openscale" {
		t.Errorf("mount %q", model.Mount)
	}
	fields := map[string]string{}
	for _, f := range model.Items.General.Fields {
		fields[f.XMLName.Local] = f.Type
		if f.Type == "TextField" && f.Mask == "" {
			t.Errorf("%s: metin alanı maskesiz", f.XMLName.Local)
		}
	}
	want := map[string]string{"enabled": "BooleanField", "listen_port": "PortField", "interface": "TextField", "memory_profile": "OptionField"}
	if fmt.Sprint(fields) != fmt.Sprint(want) {
		t.Errorf("model alanları %v", fields)
	}
	var form struct {
		Fields []struct {
			ID string `xml:"id"`
		} `xml:"field"`
	}
	if err := xml.Unmarshal([]byte(read(t, base+"mvc/app/controllers/OPNsense/OpenScale/forms/general.xml")), &form); err != nil {
		t.Fatal(err)
	}
	if len(form.Fields) != len(want) {
		t.Errorf("form %d alan", len(form.Fields))
	}
	for _, f := range form.Fields {
		if _, ok := want[strings.TrimPrefix(f.ID, "openscale.general.")]; !ok || !strings.HasPrefix(f.ID, "openscale.general.") {
			t.Errorf("form alanı %q modelde yok", f.ID)
		}
	}
	for _, rel := range []string{"mvc/app/models/OPNsense/OpenScale/Menu/Menu.xml", "mvc/app/models/OPNsense/OpenScale/ACL/ACL.xml"} {
		var v struct{ XMLName xml.Name }
		if err := xml.Unmarshal([]byte(read(t, base+rel)), &v); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
	acl := read(t, base+"mvc/app/models/OPNsense/OpenScale/ACL/ACL.xml")
	if !strings.Contains(read(t, base+"mvc/app/models/OPNsense/OpenScale/Menu/Menu.xml"), `url="/ui/openscale/"`) || !strings.Contains(acl, "<pattern>ui/openscale/*</pattern>") || !strings.Contains(acl, "<pattern>api/openscale/*</pattern>") {
		t.Errorf("menü ve ACL eşleşmiyor")
	}
	// PHP only reads/writes the model and calls configd through the base
	// classes; it never runs a command itself.
	phpFiles, _ := filepath.Glob(filepath.FromSlash(base + "mvc/app/*/OPNsense/OpenScale/*.php"))
	api, _ := filepath.Glob(filepath.FromSlash(base + "mvc/app/controllers/OPNsense/OpenScale/Api/*.php"))
	phpFiles = append(phpFiles, api...)
	if len(phpFiles) != 4 {
		t.Errorf("PHP dosyaları: %v", phpFiles)
	}
	danger := regexp.MustCompile("\\b(exec|shell_exec|system|passthru|popen|proc_open|eval|assert|configdRun|configdpRun)\\s*\\(|`")
	for _, f := range phpFiles {
		data, _ := os.ReadFile(f)
		s := string(data)
		if !strings.HasPrefix(s, "<?php\n") || !strings.Contains(s, "namespace OPNsense\\OpenScale") {
			t.Errorf("%s: başlık/ad alanı", f)
		}
		if danger.MatchString(s) {
			t.Errorf("%s: komut çalıştırıyor", f)
		}
	}
	// configd actions: fixed rc.d commands, no parameters from requests.
	act := read(t, base+"service/conf/actions.d/actions_openscale.conf")
	sections := 0
	for _, block := range strings.Split(act, "\n\n") {
		lines := strings.Split(strings.TrimSpace(block), "\n")
		if len(lines) == 0 || !strings.HasPrefix(lines[0], "[") {
			continue
		}
		sections++
		for _, l := range lines[1:] {
			k, v, _ := strings.Cut(l, ":")
			switch k {
			case "command":
				if !strings.HasPrefix(v, "/usr/local/etc/rc.d/openscale ") {
					t.Errorf("configd komutu %q", v)
				}
			case "parameters":
				if v != "" {
					t.Errorf("configd parametresi %q", v)
				}
			}
		}
	}
	if sections != 4 {
		t.Errorf("configd eylemleri %d", sections)
	}
	tpl := read(t, base+"service/templates/OPNsense/OpenScale/openscale")
	for _, ref := range regexp.MustCompile(`OPNsense\.openscale\.general\.(\w+)`).FindAllStringSubmatch(tpl, -1) {
		if _, ok := want[ref[1]]; !ok {
			t.Errorf("şablon bilinmeyen alan %q", ref[1])
		}
	}
	if strings.TrimSpace(read(t, base+"service/templates/OPNsense/OpenScale/+TARGETS")) != "openscale:/etc/rc.conf.d/openscale" {
		t.Errorf("+TARGETS")
	}
	m := jsonFile(t, "opnsense/+MANIFEST")
	deps, _ := m["deps"].(map[string]any)
	if m["name"] != "os-openscale" || deps["openscale"] == nil {
		t.Errorf("eklenti manifestosu: %v", m)
	}
	mk := read(t, "opnsense/Makefile")
	for _, want := range []string{"PLUGIN_NAME=\t\topenscale", "PLUGIN_DEPENDS=\t\topenscale", `.include "../../Mk/plugins.mk"`} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile: %q yok", want)
		}
	}
}

// ---- Qubes OS (#891)

func TestQubes(t *testing.T) {
	fw := read(t, "qubes/qubes-firewall-user-script")
	drop := strings.Index(fw, `iifname "vif*" oifname != "$IFACE" counter drop`)
	accept := strings.Index(fw, `iifname "vif*" oifname "$IFACE" accept`)
	if drop < 0 || accept < 0 || drop > accept {
		t.Errorf("kill switch: tünel dışı düşürme kabulden önce gelmeli")
	}
	// No state-based accept before the output interface is checked.
	if est := strings.Index(fw, "ct state established"); est >= 0 && est < drop {
		t.Errorf("kill switch: bağlantı durumu çıkış arayüzünden önce kabul ediliyor")
	}
	if !strings.Contains(fw, "delete table inet openscale_qubes") || strings.Contains(fw, "table ip qubes") || strings.Contains(fw, "flush ruleset") {
		t.Errorf("betik yalnızca kendi tablosunu yenilemeli")
	}
	if !strings.Contains(read(t, "qubes/50_openscale.conf"), "binds+=( '/var/lib/openscale' )") {
		t.Errorf("bind-dirs")
	}
	setup := read(t, "qubes/qube-setup.sh")
	ks := strings.Index(setup, "sh /rw/config/qubes-firewall-user-script")
	svc := strings.Index(setup, "/usr/local/lib/systemd/system/openscale-device.service")
	if ks < 0 || svc < 0 || ks > svc {
		t.Errorf("qube-setup.sh: kill switch servis kurulmadan önce yüklenmeli")
	}
	dom0 := read(t, "qubes/dom0-create-sys-openscale.sh")
	for _, want := range []string{"provides_network True", "qvm-service --enable \"$NAME\" qubes-firewall"} {
		if !strings.Contains(dom0, want) {
			t.Errorf("dom0 betiği: %q yok", want)
		}
	}
	if strings.Contains(dom0, "qvm-run") {
		t.Errorf("dom0 betiği qube'larda komut çalıştırmamalı")
	}
}

// ---- Documents and addresses

var newDocs = []string{
	"../docs/degismez-linux.md", "../docs/apparmor-selinux.md", "../docs/chromeos.md",
	"../docs/pfsense-opnsense.md", "../docs/routeros.md", "../docs/homeassistant.md", "../docs/qubes.md",
}

var (
	ipv4Re = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	urlRe  = regexp.MustCompile(`https?://([A-Za-z0-9.-]+)`)
	docNet = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("0.0.0.0/32"),
	}
)

func TestDocsAndAddresses(t *testing.T) {
	// The long-form documents live with the owner and are not published;
	// when they are present they are checked as well.
	_, docsErr := os.Stat("../docs")
	haveDocs := docsErr == nil
	var files []string
	if haveDocs {
		files = append(files, newDocs...)
	}
	for _, dir := range []string{"linux/immutable", "linux/apparmor", "linux/selinux", "pfsense", "opnsense", "routeros", "homeassistant", "qubes"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		s := read(t, filepath.ToSlash(f))
		for _, a := range ipv4Re.FindAllString(s, -1) {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				continue
			}
			ok := ip.IsPrivate() || ip.IsLoopback()
			for _, p := range docNet {
				ok = ok || p.Contains(ip)
			}
			if !ok {
				t.Errorf("%s: gerçek IP adresi %s", f, a)
			}
		}
		for _, m := range urlRe.FindAllStringSubmatch(s, -1) {
			if h := strings.ToLower(m[1]); h != "example.com" && !strings.HasSuffix(h, ".example.com") && !strings.HasSuffix(h, ".internal") && h != "localhost" && h != "127.0.0.1" {
				t.Errorf("%s: dış adres %s", f, m[0])
			}
		}
	}
	if !haveDocs {
		return
	}
	plat := read(t, "../docs/platform-destegi.md")
	for _, d := range newDocs {
		s := read(t, d)
		if !strings.Contains(s, "denenmedi") {
			t.Errorf("%s: gerçek cihazda denenmediği yazmıyor", d)
		}
		if !strings.Contains(plat, "("+filepath.Base(d)+")") {
			t.Errorf("platform-destegi.md %s belgesine bağlanmıyor", filepath.Base(d))
		}
	}
	notes := read(t, "../docs/surum-notlari-1.0.0-beta.2.md")
	if !strings.Contains(notes, "## Platform paketleri") {
		t.Errorf("sürüm notlarında Platform paketleri bölümü yok")
	}
}
