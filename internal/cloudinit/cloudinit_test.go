package cloudinit

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
	"testing"
)

const (
	testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpenScaleTestKeyOnlyForUnitTests0000000 owner@laptop"
	testSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func base() Options {
	return Options{
		Role: RoleCoordinator, Hostname: "vpn", SSHKeys: []string{testKey},
		PackageURL: "https://indirme.ornek.com/openscale_1.2.3_amd64.deb", PackageSHA256: testSum, PackageSize: 12345,
	}
}

func TestGenerateCoordinator(t *testing.T) {
	o := base()
	o.TCPListen = 443
	out, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"#cloud-config\n", "ssh_pwauth: false", "'" + testKey + "'", "PasswordAuthentication no",
		"APT::Periodic::Unattended-Upgrade \"1\";", "udp dport 41820 accept", "tcp dport 443 accept",
		"OPENSCALE_TCP_LISTEN=:443", "sha256sum -c", "= '12345'", "coordinator keygen", "server audit --role coordinator",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "auth.key") {
		t.Fatal("unexpected content")
	}
	// Every write_files content line is indented; no line starts a new
	// YAML key by accident.
	for _, line := range strings.Split(s, "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") {
			continue
		}
		if !regexp.MustCompile(`^[a-z_]+:`).MatchString(line) {
			t.Errorf("stray top-level line %q", line)
		}
	}
}

func TestGenerateExitNode(t *testing.T) {
	o := base()
	o.Role, o.AuthKey, o.ListenPort = RoleExit, "osauth1.QUJD-_x", 41900
	out, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	m := regexp.MustCompile(`encoding: gz\+b64\n    content: (\S+)`).FindStringSubmatch(s)
	if m == nil {
		t.Fatal("no encoded key")
	}
	raw, _ := base64.StdEncoding.DecodeString(m[1])
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := io.ReadAll(zr)
	if string(key) != o.AuthKey+"\n" {
		t.Fatalf("key = %q", key)
	}
	for _, want := range []string{"preauth-join", "rm -f \"$work/auth.key\"", "udp dport 41900", "--listen-port 41900", "openscale-device.service"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, o.AuthKey) {
		t.Fatal("key in clear text")
	}
}

func TestValidateRejectsInjection(t *testing.T) {
	for name, mut := range map[string]func(*Options){
		"role":         func(o *Options) { o.Role = "x" },
		"hostname":     func(o *Options) { o.Hostname = "a;reboot" },
		"no ssh":       func(o *Options) { o.SSHKeys = nil },
		"ssh newline":  func(o *Options) { o.SSHKeys = []string{testKey + "\nruncmd: [x]"} },
		"ssh quote":    func(o *Options) { o.SSHKeys = []string{"ssh-ed25519 AAAA x'y"} },
		"http":         func(o *Options) { o.PackageURL = "http://indirme.ornek.com/a.deb" },
		"url quote":    func(o *Options) { o.PackageURL = "https://indirme.ornek.com/a'$(id).deb" },
		"url not deb":  func(o *Options) { o.PackageURL = "https://indirme.ornek.com/a.sh" },
		"sum":          func(o *Options) { o.PackageSHA256 = "zz" },
		"size":         func(o *Options) { o.PackageSize = 0 },
		"exit no key":  func(o *Options) { o.Role = RoleExit },
		"exit tcp":     func(o *Options) { o.Role, o.AuthKey, o.TCPListen = RoleExit, "osauth1.a", 443 },
		"coord key":    func(o *Options) { o.AuthKey = "osauth1.a" },
		"bad auth key": func(o *Options) { o.Role, o.AuthKey = RoleExit, "osauth1.a b" },
		"port":         func(o *Options) { o.ListenPort = 70000 },
	} {
		o := base()
		mut(&o)
		if _, err := Generate(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzGenerate(f *testing.F) {
	f.Add("vpn", testKey, "https://indirme.ornek.com/openscale_1_amd64.deb", "osauth1.abc")
	f.Fuzz(func(t *testing.T, host, key, url, auth string) {
		o := base()
		o.Hostname, o.SSHKeys, o.PackageURL = host, []string{key}, url
		if strings.HasPrefix(auth, "osauth1.") {
			o.Role, o.AuthKey = RoleExit, auth
		}
		out, err := Generate(o)
		if err != nil {
			return
		}
		// Accepted values never carry characters that could leave their
		// YAML scalar or shell quotes.
		for _, v := range []string{o.Hostname, o.SSHKeys[0], o.PackageURL} {
			if strings.ContainsAny(v, "'\"\n\r`$\\;") {
				t.Fatalf("unsafe value accepted: %q", v)
			}
		}
		if !bytes.HasPrefix(out, []byte("#cloud-config\n")) {
			t.Fatal("no header")
		}
	})
}
