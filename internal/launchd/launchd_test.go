package launchd

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestPlistWellFormedAndEscaped(t *testing.T) {
	j := Job{
		Label:              "com.openscale.device",
		Program:            []string{"/usr/local/bin/openscale", "up", "--config", "/etc/openscale/device.json", "<&>"},
		Marker:             "made by test",
		RunAtLoad:          true,
		KeepAliveOnFailure: true,
		ThrottleInterval:   10,
		ExitTimeOut:        30,
		Umask:              0o077,
		WorkingDirectory:   "/var/db/openscale/device",
		StdoutPath:         "/var/log/openscale-device.log",
		StderrPath:         "/var/log/openscale-device.log",
		Env:                map[string]string{"PATH": "/usr/bin:/bin", "A": "x&y"},
	}
	data, err := Plist(j)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.HasPrefix(s, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Fatal("XML declaration must be first")
	}
	for _, want := range []string{
		"<string>com.openscale.device</string>",
		"<string>&lt;&amp;&gt;</string>",
		"<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>",
		"<key>Umask</key>\n\t<integer>63</integer>",
		"<key>UserName</key>\n\t<string>root</string>",
		"<key>A</key>\n\t\t<string>x&amp;y</string>\n\t\t<key>PATH</key>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %q:\n%s", want, s)
		}
	}
	// The whole document must parse as XML (the DOCTYPE is skipped by the
	// decoder in non-strict mode).
	d := xml.NewDecoder(strings.NewReader(s))
	d.Strict = false
	for {
		_, err := d.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("not well-formed: %v", err)
		}
	}
	if !HasMarker(data, "made by test") || HasMarker(data, "other") || HasMarker(data, "") {
		t.Fatal("marker check")
	}
}

func TestPlistRejectsBadInput(t *testing.T) {
	good := Job{Label: "com.openscale.x", Program: []string{"/bin/true"}}
	if _, err := Plist(good); err != nil {
		t.Fatal(err)
	}
	bad := []Job{
		{Label: "com/openscale", Program: []string{"/bin/true"}},
		{Label: "", Program: []string{"/bin/true"}},
		{Label: "com.openscale.x", Program: []string{"bin/true"}},
		{Label: "com.openscale.x", Program: []string{"/bin/../bin/true"}},
		{Label: "com.openscale.x"},
		{Label: "com.openscale.x", Program: []string{"/bin/true", "a\nb"}},
		{Label: "com.openscale.x", Program: []string{"/bin/true"}, Marker: "a -- b"},
		{Label: "com.openscale.x", Program: []string{"/bin/true"}, StdoutPath: "relative.log"},
		{Label: "com.openscale.x", Program: []string{"/bin/true"}, Env: map[string]string{"A=B": "c"}},
		{Label: "com.openscale.x", Program: []string{"/bin/true"}, Umask: 0o1000},
	}
	for i, j := range bad {
		if _, err := Plist(j); err == nil {
			t.Errorf("case %d accepted: %+v", i, j)
		}
	}
}

func TestParsePrintAndDisabled(t *testing.T) {
	out := []byte(`system/com.openscale.device = {
	active count = 1
	path = /Library/LaunchDaemons/com.openscale.device.plist
	state = running

	program = /usr/local/bin/openscale
	pid = 512
	endpoints = {
		state = whatever
	}
}`)
	st := ParsePrint(out)
	if st.State != "running" || st.PID != 512 || st.Path != "/Library/LaunchDaemons/com.openscale.device.plist" {
		t.Fatalf("print = %+v", st)
	}
	dis := []byte("disabled services = {\n\t\"com.openscale.device\" => disabled\n\t\"com.apple.ftpd\" => enabled\n}\n")
	if !Disabled(dis, "com.openscale.device") || Disabled(dis, "com.apple.ftpd") || Disabled(dis, "com.openscale") {
		t.Fatal("print-disabled parse")
	}
	if !Disabled([]byte("\t\"com.openscale.device\" => true\n"), "com.openscale.device") {
		t.Fatal("old print-disabled form")
	}
	if Path("com.openscale.device") != "/Library/LaunchDaemons/com.openscale.device.plist" || Target("x") != "system/x" {
		t.Fatal("paths")
	}
}
