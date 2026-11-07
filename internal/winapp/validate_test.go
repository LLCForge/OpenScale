package winapp

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestValidateProgramPath(t *testing.T) {
	ok := []string{
		`C:\Program Files\OpenScale\openscale.exe`,
		`d:\tools\OpenScale.EXE`,
		`C:\Users\Çağrı Şık\İndirilenler\openscale.exe`,
	}
	for _, p := range ok {
		if got, err := validateProgramPath(p); err != nil || got != p {
			t.Errorf("validateProgramPath(%q) = %q, %v; want ok", p, got, err)
		}
	}
	bad := []string{
		"",
		`openscale.exe`,
		`\Program Files\openscale.exe`,
		`\\server\share\openscale.exe`,
		`C:openscale.exe`,
		`C:/Program Files/openscale.exe`,
		`C:\Program Files\OpenScale\openscale.dll`,
		`C:\Program Files\OpenScale`,
		`C:\a\..\openscale.exe`,
		`C:\a\.\openscale.exe`,
		`C:\a\\openscale.exe`,
		`C:\a" dir=out "\openscale.exe`,
		"C:\\a\nprogram=x\\openscale.exe",
		"C:\\a\x00\\openscale.exe",
		`C:\a\b:stream.exe`,
		`C:\a\b?.exe`,
		`C:\a\trailing.\openscale.exe`,
		`C:\a\trailing \openscale.exe`,
		`C:\` + strings.Repeat("a", maxProgramPathLen) + `.exe`,
	}
	for _, p := range bad {
		if _, err := validateProgramPath(p); err == nil {
			t.Errorf("validateProgramPath(%q) accepted; want error", p)
		}
	}
}

func TestValidateIPv4CIDR(t *testing.T) {
	cases := map[string]string{
		"100.80.0.0/16":  "100.80.0.0/16",
		"100.80.12.7/16": "100.80.0.0/16",
		"10.0.0.1/32":    "10.0.0.1/32",
	}
	for in, want := range cases {
		got, err := validateIPv4CIDR(in)
		if err != nil || got != want {
			t.Errorf("validateIPv4CIDR(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "100.80.0.0", "0.0.0.0/0", "fd7a::/48", "::ffff:100.80.0.0/112",
		"100.80.0.0/33", "100.80.0.0/16 any", "100.80.0.0/16,1.2.3.4", "any", "localsubnet",
	} {
		if _, err := validateIPv4CIDR(in); err == nil {
			t.Errorf("validateIPv4CIDR(%q) accepted; want error", in)
		}
	}
}

func TestFirewallArgs(t *testing.T) {
	exe := `C:\Program Files\OpenScale\openscale.exe`
	add := firewallAddArgs(exe, "100.80.0.0/16")
	if len(add) != 2 {
		t.Fatalf("got %d add commands, want 2", len(add))
	}
	joined := strings.Join(add[0], "|")
	for _, want := range []string{"name=OpenScale (UDP)", "dir=in", "protocol=UDP", "program=" + exe, "profile=any"} {
		if !strings.Contains(joined, want) {
			t.Errorf("UDP rule args %q missing %q", joined, want)
		}
	}
	joined = strings.Join(add[1], "|")
	for _, want := range []string{"name=OpenScale (ping)", "protocol=icmpv4:8,any", "remoteip=100.80.0.0/16"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ping rule args %q missing %q", joined, want)
		}
	}
	del := firewallDeleteArgs()
	if len(del) != 2 || del[0][len(del[0])-1] != "name=OpenScale (UDP)" || del[1][len(del[1])-1] != "name=OpenScale (ping)" {
		t.Errorf("unexpected delete args: %q", del)
	}
}

func TestValidateLoopbackURL(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:41641/",
		"http://127.0.0.1:8080/devices?q=1#x",
		"http://127.0.0.1/",
		"http://127.1.2.3:80/",
		"http://[::1]:8080/",
	}
	for _, u := range ok {
		if _, err := validateLoopbackURL(u); err != nil {
			t.Errorf("validateLoopbackURL(%q) = %v; want ok", u, err)
		}
	}
	bad := []string{
		"",
		"https://127.0.0.1/",
		"file:///C:/Windows/System32/calc.exe",
		"http://localhost:8080/",
		"http://example.com/",
		"http://127.0.0.1.example.com/",
		"http://user:pw@127.0.0.1/",
		"http://10.0.0.1/",
		"http://[fe80::1%25eth0]/",
		"http://127.0.0.1:0/",
		"http://127.0.0.1:99999/",
		"http://127.0.0.1:/",
		"http://127.0.0.1/a b",
		"http://127.0.0.1/\"&calc",
		"http:127.0.0.1",
		"javascript:alert(1)",
		`\\evil\share`,
		"http://127.0.0.1/" + strings.Repeat("a", maxURLLen),
	}
	for _, u := range bad {
		if _, err := validateLoopbackURL(u); err == nil {
			t.Errorf("validateLoopbackURL(%q) accepted; want error", u)
		}
	}
}

func TestCopyUTF16(t *testing.T) {
	buf := make([]uint16, 5)
	copyUTF16(buf, "abcdefgh")
	if got := string(utf16.Decode(buf[:4])); got != "abcd" || buf[4] != 0 {
		t.Errorf("truncation: got %q, terminator %d", got, buf[4])
	}

	// "abc" + U+1F600 (surrogate pair) must not be split.
	buf = make([]uint16, 5)
	copyUTF16(buf, "abc\U0001F600")
	if buf[3] != 0 {
		t.Errorf("lone high surrogate kept: %v", buf)
	}

	buf = make([]uint16, 8)
	copyUTF16(buf, "a\x00b")
	if got := string(utf16.Decode(buf[:2])); got != "ab" {
		t.Errorf("NUL not removed: %q", got)
	}

	copyUTF16(nil, "x") // must not panic
}

func TestMenuLabel(t *testing.T) {
	if got := menuLabel("R&D\nPC\x00"); got != "R&&D PC" {
		t.Errorf("menuLabel = %q", got)
	}
}

func TestErrUnsupportedMessage(t *testing.T) {
	if ErrUnsupported.Error() != "bu özellik yalnızca Windows'ta" {
		t.Errorf("unexpected message %q", ErrUnsupported)
	}
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Fatal("sentinel comparison broken")
	}
}
