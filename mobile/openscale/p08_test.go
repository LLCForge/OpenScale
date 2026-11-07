package openscale

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
)

func newInviteCode(t *testing.T) string {
	t.Helper()
	tn := newJoinedPhone(t)
	created, err := tn.net.CreateInviteWith(testPass, time.Now(), admin.InviteRequest{Life: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return created.Code
}

func apdu(t *testing.T, tag *NfcTag, hexCmd []byte) ([]byte, []byte) {
	t.Helper()
	r := tag.Process(hexCmd)
	if len(r) < 2 {
		t.Fatalf("short response %x", r)
	}
	return r[:len(r)-2], r[len(r)-2:]
}

// readTag behaves like Android's IsoDep NDEF reader: select the
// application, read the capability container, read NLEN, then the message
// in MLe-sized chunks.
func readTag(t *testing.T, tag *NfcTag) []byte {
	t.Helper()
	if _, sw := apdu(t, tag, append([]byte{0x00, 0xA4, 0x04, 0x00, 0x07}, append(nfcAID, 0x00)...)); !bytes.Equal(sw, swOK) {
		t.Fatalf("select app: %x", sw)
	}
	if _, sw := apdu(t, tag, []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03}); !bytes.Equal(sw, swOK) {
		t.Fatalf("select cc: %x", sw)
	}
	cc, sw := apdu(t, tag, []byte{0x00, 0xB0, 0x00, 0x00, 0x0F})
	if !bytes.Equal(sw, swOK) || len(cc) != 15 || cc[2] != 0x20 || cc[13] != 0x00 || cc[14] != 0xFF {
		t.Fatalf("cc %x %x", cc, sw)
	}
	mle := int(binary.BigEndian.Uint16(cc[3:]))
	fileID := cc[9:11]
	if _, sw := apdu(t, tag, append([]byte{0x00, 0xA4, 0x00, 0x0C, 0x02}, fileID...)); !bytes.Equal(sw, swOK) {
		t.Fatalf("select ndef: %x", sw)
	}
	nlen, sw := apdu(t, tag, []byte{0x00, 0xB0, 0x00, 0x00, 0x02})
	if !bytes.Equal(sw, swOK) || len(nlen) != 2 {
		t.Fatalf("nlen %x %x", nlen, sw)
	}
	if tag.Delivered() {
		t.Fatal("delivered after reading only NLEN")
	}
	n := int(binary.BigEndian.Uint16(nlen))
	var msg []byte
	for off := 2; off < 2+n; {
		le := min(mle, 2+n-off)
		chunk, sw := apdu(t, tag, []byte{0x00, 0xB0, byte(off >> 8), byte(off), byte(le)})
		if !bytes.Equal(sw, swOK) || len(chunk) == 0 {
			t.Fatalf("read at %d: %x", off, sw)
		}
		msg = append(msg, chunk...)
		off += len(chunk)
	}
	return msg
}

func TestNfcTagRoundTrip(t *testing.T) {
	code := newInviteCode(t)
	tag, err := NewNfcTag("  " + code + "\n")
	if err != nil {
		t.Fatal(err)
	}
	// Writes are refused before and during a read.
	if _, sw := apdu(t, tag, []byte{0x00, 0xD6, 0x00, 0x00, 0x01, 0x00}); !bytes.Equal(sw, swSecurity) {
		t.Fatalf("update: %x", sw)
	}
	// A file cannot be selected before the application.
	if _, sw := apdu(t, tag, []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04}); !bytes.Equal(sw, swNotFound) {
		t.Fatalf("file before app: %x", sw)
	}
	msg := readTag(t, tag)
	if !tag.Delivered() {
		t.Fatal("not delivered after a full read")
	}
	got, err := NfcInviteFromNDEF(msg)
	if err != nil || got != code {
		t.Fatalf("parsed %q, %v", got, err)
	}
	var r scanResult
	if err := json.Unmarshal([]byte(ClassifyScan(got)), &r); err != nil || r.Kind != scanInvite {
		t.Fatalf("classified %+v %v", r, err)
	}
	// One read only: afterwards the tag is gone.
	if _, sw := apdu(t, tag, append([]byte{0x00, 0xA4, 0x04, 0x00, 0x07}, nfcAID...)); !bytes.Equal(sw, swNotFound) {
		t.Fatalf("second read: %x", sw)
	}
}

func TestNfcTagRefusals(t *testing.T) {
	for _, bad := range []string{"", "merhaba", "openscale-invite:"} {
		if _, err := NewNfcTag(bad); err == nil {
			t.Errorf("invite %q accepted", bad)
		}
	}
	tag, err := NewNfcTag(newInviteCode(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cmd []byte
		sw  []byte
	}{
		{[]byte{0x00}, swWrongLength},
		{make([]byte, nfcMaxAPDU+1), swWrongLength},
		{[]byte{0x80, 0xA4, 0x04, 0x00, 0x01, 0x00}, swCLANotSupport},
		{[]byte{0x00, 0xCA, 0x00, 0x00}, swINSNotSupport},
		{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 1, 2, 3, 4, 5}, swNotFound},
		{[]byte{0x00, 0xA4, 0x04, 0x00, 0x09, 1}, swWrongLength},
		{[]byte{0x00, 0xA4, 0x02, 0x00, 0x01, 0x00}, swWrongP1P2},
		{[]byte{0x00, 0xB0, 0x00, 0x00, 0x0F}, swNotFound},
	} {
		if _, sw := apdu(t, tag, tc.cmd); !bytes.Equal(sw, tc.sw) {
			t.Errorf("%x: %x, want %x", tc.cmd, sw, tc.sw)
		}
	}
	apdu(t, tag, append([]byte{0x00, 0xA4, 0x04, 0x00, 0x07}, nfcAID...))
	apdu(t, tag, []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04})
	if _, sw := apdu(t, tag, []byte{0x00, 0xB0, 0x7F, 0xFF, 0x01}); !bytes.Equal(sw, swWrongP1P2) {
		t.Fatalf("read past end: %x", sw)
	}
	tag.Wipe()
	if _, sw := apdu(t, tag, []byte{0x00, 0xB0, 0x00, 0x00, 0x02}); !bytes.Equal(sw, swNotFound) || tag.Delivered() {
		t.Fatalf("wiped tag answered: %x", sw)
	}
}

func TestNfcInviteFromNDEF(t *testing.T) {
	long := strings.Repeat("a", 300)
	two := append(ndefMediaRecord("text/plain", []byte("x")), ndefMediaRecord(NFCInviteMIME, []byte(long))...)
	two[0] &^= 0x40 // first record: not message end
	two[len(ndefMediaRecord("text/plain", []byte("x")))] &^= 0x80
	if got, err := NfcInviteFromNDEF(two); err != nil || got != long {
		t.Fatalf("two records: %q %v", got, err)
	}
	upper := ndefMediaRecord("Application/VND.OpenScale.Invite", []byte("kod"))
	if got, err := NfcInviteFromNDEF(upper); err != nil || got != "kod" {
		t.Fatalf("mime case: %q %v", got, err)
	}
	chunked := ndefMediaRecord(NFCInviteMIME, []byte("kod"))
	chunked[0] |= 0x20
	notBegin := ndefMediaRecord(NFCInviteMIME, []byte("kod"))
	notBegin[0] &^= 0x80
	trailing := append(ndefMediaRecord("text/plain", []byte("x")), 0x00)
	noEnd := ndefMediaRecord("text/plain", []byte("x"))
	noEnd[0] &^= 0x40
	for name, bad := range map[string][]byte{
		"empty":     nil,
		"short":     {0xD2},
		"chunked":   chunked,
		"not begin": notBegin,
		"trailing":  trailing,
		"no end":    noEnd,
		"other":     ndefMediaRecord("text/plain", []byte("kod")),
		"bad utf8":  ndefMediaRecord(NFCInviteMIME, []byte{0xff, 0xfe}),
		"huge":      make([]byte, maxNDEF+1),
		"truncated": ndefMediaRecord(NFCInviteMIME, []byte("kod"))[:5],
	} {
		if _, err := NfcInviteFromNDEF(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzNfcTagProcess(f *testing.F) {
	f.Add(append([]byte{0x00, 0xA4, 0x04, 0x00, 0x07}, nfcAID...))
	f.Add([]byte{0x00, 0xB0, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04})
	tag := &NfcTag{cc: make([]byte, 15), ndef: append([]byte{0x00, 0x05}, ndefMediaRecord(NFCInviteMIME, []byte("x"))[:5]...)}
	f.Fuzz(func(t *testing.T, cmd []byte) {
		r := tag.Process(cmd)
		if len(r) < 2 || len(r) > nfcMLe+2 {
			t.Fatalf("response length %d", len(r))
		}
	})
}

func FuzzNfcInviteFromNDEF(f *testing.F) {
	f.Add(ndefMediaRecord(NFCInviteMIME, []byte("openscale-invite:x")))
	f.Add(ndefMediaRecord(NFCInviteMIME, bytes.Repeat([]byte("a"), 300)))
	f.Add([]byte{0x91, 0x01, 0x01, 'T', 0x00, 0x51, 0x01, 0x01, 'U', 0x00})
	f.Fuzz(func(t *testing.T, msg []byte) {
		s, err := NfcInviteFromNDEF(msg)
		if err == nil && (len(s) > maxNFCText || s == "" && len(msg) == 0) {
			t.Fatalf("accepted %q", s)
		}
	})
}

func TestUsageCounter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	out, err := UsageSummary(path)
	if err != nil || out != `{"version":1,"months":[]}` {
		t.Fatalf("empty summary %s %v", out, err)
	}
	for _, s := range []struct {
		month, net string
		rx, tx     int
	}{
		{"2026-10", "cellular", 600, 100},
		{"2026-10", "wifi", 5, 6},
		{"2026-10", "ethernet", 1, 1},
		{"2026-10", "cellular", 50, 50},
		{"2026-09", "cellular", 7, 0},
		{"2026-10", "wifi", 0, 0},
	} {
		if err := UsageAdd(path, s.month, s.net, s.rx, s.tx); err != nil {
			t.Fatal(err)
		}
	}
	var f usageFile
	out, _ = UsageSummary(path)
	if err := json.Unmarshal([]byte(out), &f); err != nil || len(f.Months) != 2 || f.Months[0].Month != "2026-09" {
		t.Fatalf("summary %s %v", out, err)
	}
	m := f.Months[1]
	if m.Cellular != (usageBytes{650, 150}) || m.WiFi != (usageBytes{5, 6}) || m.Other != (usageBytes{1, 1}) {
		t.Fatalf("month %+v", m)
	}
	var c usageCheck
	out, err = UsageCheck(path, "2026-10", 1000)
	if err != nil || json.Unmarshal([]byte(out), &c) != nil || c.CellularBytes != 800 || c.Percent != 80 || !c.Warn || c.Over {
		t.Fatalf("check %s %v", out, err)
	}
	out, _ = UsageCheck(path, "2026-10", 800)
	if json.Unmarshal([]byte(out), &c) != nil || !c.Over || c.Percent != 100 {
		t.Fatalf("over %s", out)
	}
	out, _ = UsageCheck(path, "2026-10", 1)
	if json.Unmarshal([]byte(out), &c) != nil || c.Percent != 1000 {
		t.Fatalf("capped %s", out)
	}
	out, _ = UsageCheck(path, "2026-10", 0)
	if json.Unmarshal([]byte(out), &c) != nil || c.Warn || c.Over || c.Percent != 0 {
		t.Fatalf("no limit %s", out)
	}
	// Only the last 13 months are kept; an older month is dropped.
	for i := 1; i <= 14; i++ {
		month := "2027-" + []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"}[(i-1)%12]
		if i > 12 {
			month = "2028-0" + string(rune('0'+i-12))
		}
		if err := UsageAdd(path, month, "wifi", 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := UsageAdd(path, "2020-01", "wifi", 1, 1); err != nil {
		t.Fatal(err)
	}
	out, _ = UsageSummary(path)
	if json.Unmarshal([]byte(out), &f) != nil || len(f.Months) != maxUsageMonths || f.Months[0].Month != "2027-02" || strings.Contains(out, "2020-01") {
		t.Fatalf("kept months %s", out)
	}
	for _, bad := range []struct {
		path, month string
		rx          int
	}{
		{"usage.json", "2026-10", 1},
		{path, "2026-13", 1},
		{path, "2026-1", 1},
		{path, "26-10-01", 1},
		{path, "2026-10", -1},
		{path, "2026-10", maxUsageDelta + 1},
	} {
		if err := UsageAdd(bad.path, bad.month, "wifi", bad.rx, 0); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// A damaged file starts over.
	if err := UsageReset(path); err != nil {
		t.Fatal(err)
	}
	if err := UsageReset(path); err != nil {
		t.Fatal("reset of a missing file:", err)
	}
}

func TestNetworkID(t *testing.T) {
	salt, err := NewNetworkIDSalt()
	if err != nil || len(salt) != saltHexLen {
		t.Fatal(salt, err)
	}
	other, _ := NewNetworkIDSalt()
	a, err := NetworkID(salt, "192.168.1.1", "192.168.1.1", "192.168.1.1, fe80::1%wlan0, 2001:db8::53", "Home.LAN.", "192.168.1.77/24")
	if err != nil || !validNetID(a) {
		t.Fatal(a, err)
	}
	// Order, zones, case, global IPv6 DNS and the host part do not matter.
	b, err := NetworkID(salt, " 192.168.1.1 ", "192.168.1.1", "fe80::1,192.168.1.1,2001:db8::99,192.168.1.1", "home.lan", "192.168.1.5/24")
	if err != nil || a != b {
		t.Fatalf("%s != %s (%v)", a, b, err)
	}
	if c, _ := NetworkID(other, "192.168.1.1", "192.168.1.1", "192.168.1.1, fe80::1", "home.lan", "192.168.1.0/24"); c == a {
		t.Fatal("identity does not depend on the salt")
	}
	if c, _ := NetworkID(salt, "192.168.1.254", "192.168.1.1", "192.168.1.1, fe80::1", "home.lan", "192.168.1.0/24"); c == a {
		t.Fatal("identity does not depend on the gateway")
	}
	if _, err := NetworkID(salt, "", "", "2001:db8::53", "", ""); err == nil {
		t.Fatal("identity from a global IPv6 DNS only")
	}
	for _, bad := range [][]string{
		{"zz", "192.168.1.1", "", "", "", ""},
		{salt, "", "", "", "", ""},
		{salt, "fe80::1", "", "", "", ""},
		{salt, "300.1.1.1", "", "", "", ""},
		{salt, "10.0.0.1", "", "x", "", ""},
		{salt, "10.0.0.1", "", "", "evil\nlan", ""},
		{salt, "10.0.0.1", "", "", "", "10.0.0.0/33"},
		{salt, "10.0.0.1", "", strings.Repeat("10.0.0.1,", 200), "", ""},
	} {
		if _, err := NetworkID(bad[0], bad[1], bad[2], bad[3], bad[4], bad[5]); err == nil {
			t.Errorf("%q accepted", bad[1:])
		}
	}

	policy := `{"rules":[
		{"network":"wifi","net_id":"` + a + `","exit_node":""},
		{"network":"wifi","exit_node":"home"}
	]}`
	if got, err := ExitNodeForNetworkID(policy, "wifi", "", a, "x"); err != nil || got != "" {
		t.Fatalf("home network: %q %v", got, err)
	}
	if got, err := ExitNodeForNetworkID(policy, "wifi", "", "n1-000000000000000000000000", "x"); err != nil || got != "home" {
		t.Fatalf("other network: %q %v", got, err)
	}
	if got, err := ExitNodeForNetworkID(policy, "wifi", "", "", "x"); err != nil || got != "home" {
		t.Fatalf("unknown identity: %q %v", got, err)
	}
	if got, _ := ExitNodeForNetworkID(policy, "wifi", "", "çöp", "x"); got != "home" {
		t.Fatalf("garbage identity matched: %q", got)
	}
	if got, _ := ExitNodeForNetwork(policy, "wifi", "", "x"); got != "home" {
		t.Fatalf("old call matched an identity rule: %q", got)
	}
	for _, bad := range []string{
		`{"rules":[{"network":"cellular","net_id":"` + a + `","exit_node":""}]}`,
		`{"rules":[{"network":"any","net_id":"` + a + `","exit_node":""}]}`,
		`{"rules":[{"network":"wifi","net_id":"n1-XYZ","exit_node":""}]}`,
	} {
		if _, err := ExitNodeForNetworkID(bad, "wifi", "", a, ""); err == nil {
			t.Errorf("policy %s accepted", bad)
		}
	}
	out, err := CheckNetworkPolicy(filepath.Join(t.TempDir(), "yok"), policy)
	if err != nil || !strings.Contains(out, "ağ kimliği doğrulanmaz") {
		t.Fatalf("warnings %s %v", out, err)
	}
}

func TestExitNodes(t *testing.T) {
	tn := newJoinedPhone(t)
	out, err := ExitNodes(tn.dir)
	if err != nil || out != `["home"]` {
		t.Fatalf("exit nodes %s %v", out, err)
	}
	if _, err := ExitNodes(filepath.Join(t.TempDir(), "yok")); err == nil {
		t.Fatal("not joined state accepted")
	}
	if _, err := ExitNodes("göreli"); err == nil {
		t.Fatal("relative state dir accepted")
	}
}
