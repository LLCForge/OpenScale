//go:build windows

package winapp

import (
	"encoding/xml"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestTrayTaskXML(t *testing.T) {
	exe := `C:\Program Files\A&B <x>\openscale.exe`
	def, err := trayTaskXML(exe)
	if err != nil {
		t.Fatal(err)
	}
	var task struct {
		Principal struct {
			GroupID  string `xml:"GroupId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principals>Principal"`
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Actions>Exec"`
	}
	// The declaration says UTF-16 (what schtasks reads); the content is ASCII-safe.
	d := xml.NewDecoder(strings.NewReader(strings.Replace(def, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
	if err := d.Decode(&task); err != nil {
		t.Fatal(err)
	}
	if task.Exec.Command != exe || task.Exec.Arguments != "autostart run" {
		t.Fatalf("exec = %+v", task.Exec)
	}
	if task.Principal.GroupID != usersGroupSID || task.Principal.RunLevel != "HighestAvailable" {
		t.Fatalf("principal = %+v", task.Principal)
	}
	if _, err := trayTaskXML("openscale.exe"); err == nil {
		t.Fatal("relative program path accepted")
	}
}

func TestEncodeUTF16LE(t *testing.T) {
	b := encodeUTF16LE("ağ")
	if b[0] != 0xFF || b[1] != 0xFE || len(b) != 6 {
		t.Fatalf("% x", b)
	}
	u := []uint16{uint16(b[2]) | uint16(b[3])<<8, uint16(b[4]) | uint16(b[5])<<8}
	if string(utf16.Decode(u)) != "ağ" {
		t.Fatalf("round trip = %q", string(utf16.Decode(u)))
	}
}
