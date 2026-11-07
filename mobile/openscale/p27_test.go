package openscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image/png"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/qr"
	"github.com/openscale/openscale/internal/trust"
)

func TestPlanPerAppSplit(t *testing.T) {
	tn := newJoinedPhone(t)
	out, err := Plan(tn.dir, tn.secrets, `{"exit_node":"home","apps_mode":"include","apps":["org.mozilla.firefox","com.example.mail"]}`)
	if err != nil {
		t.Fatal(err)
	}
	var p vpnPlan
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if p.FullTunnel || !reflect.DeepEqual(p.AllowedApps, []string{"com.example.mail", "org.mozilla.firefox"}) || p.DisallowedApps != nil {
		t.Fatalf("include plan = %+v", p)
	}
	out, err = Plan(tn.dir, tn.secrets, `{"apps_mode":"exclude","apps":["com.bank.app"]}`)
	if err != nil {
		t.Fatal(err)
	}
	p = vpnPlan{}
	_ = json.Unmarshal([]byte(out), &p)
	if !reflect.DeepEqual(p.DisallowedApps, []string{"com.bank.app"}) || p.AllowedApps != nil {
		t.Fatalf("exclude plan = %+v", p)
	}
	for _, bad := range []string{
		`{"apps_mode":"include"}`,
		`{"apps_mode":"include","apps":[]}`,
		`{"apps":["com.a.b"]}`,
		`{"apps_mode":"both","apps":["com.a.b"]}`,
		`{"apps_mode":"exclude","apps":["noDot"]}`,
		`{"apps_mode":"exclude","apps":["com..x"]}`,
		`{"apps_mode":"exclude","apps":["com.1x"]}`,
		`{"apps_mode":"exclude","apps":["com.x;rm"]}`,
		`{"apps_mode":"exclude","apps":["com.a.b","com.a.b"]}`,
	} {
		if _, err := Plan(tn.dir, tn.secrets, bad); err == nil {
			t.Errorf("options %s accepted", bad)
		}
	}
	many := make([]string, maxApps+1)
	for i := range many {
		many[i] = "com.example.app" + strings.Repeat("x", i%7) + "n" + string(rune('a'+i%26)) + "." + "p" + strings.Repeat("q", i/26)
	}
	data, _ := json.Marshal(startOptions{AppsMode: appsExclude, Apps: many})
	if _, err := parseOptions(string(data)); err == nil {
		t.Fatal("too many apps accepted")
	}
}

func TestValidPackage(t *testing.T) {
	for s, want := range map[string]bool{
		"org.openscale.android": true, "a.b": true, "com.example_app.x1": true, "A.B": true,
		"": false, "single": false, ".a.b": false, "a.b.": false, "a..b": false, "a.1b": false,
		"a._b": false, "a.b-c": false, "ç.a": false, strings.Repeat("a", 254) + ".b": false,
	} {
		if got := validPackage(s); got != want {
			t.Errorf("validPackage(%q) = %v", s, got)
		}
	}
}

func TestDecodeQRAndClassifyInvite(t *testing.T) {
	tn := newJoinedPhone(t)
	created, err := tn.net.CreateInviteWith(testPass, time.Now(), admin.InviteRequest{Life: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// The owner's screen shows the code as a QR code; the phone's camera
	// sees it as a luminance frame.
	code, err := qr.EncodeText(created.Code, qr.L)
	if err != nil {
		t.Fatal(err)
	}
	img, err := code.Image(4)
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	stride := b.Dx() + 16
	frame := bytes.Repeat([]byte{128}, stride*b.Dy())
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			r, _, _, _ := img.At(x, y).RGBA()
			frame[y*stride+x] = byte(r >> 8)
		}
	}
	text, err := DecodeQR(frame, b.Dx(), b.Dy(), stride)
	if err != nil || text != created.Code {
		t.Fatalf("decoded %q, %v", text, err)
	}
	var r scanResult
	if err := json.Unmarshal([]byte(ClassifyScan(text)), &r); err != nil {
		t.Fatal(err)
	}
	doc, _ := tn.net.Document()
	if r.Kind != scanInvite || r.NetworkID != doc.NetworkID || r.RootFingerprint != tn.net.RootFingerprint() || len(trust.NormalizeSAS(r.RootSAS)) != trust.SASDigits || r.Coordinator != "192.0.2.1:41820" {
		t.Fatalf("classified %+v", r)
	}
	if strings.Contains(ClassifyScan(text), `"s"`) {
		t.Fatal("classification leaks the invite seed")
	}
	if _, err := DecodeQR(bytes.Repeat([]byte{255}, 100*100), 100, 100, 100); err == nil {
		t.Fatal("blank frame decoded")
	}
	if _, err := DecodeQR(make([]byte, 10), 100, 100, 100); err == nil {
		t.Fatal("short frame accepted")
	}
}

func TestClassifyScanKinds(t *testing.T) {
	for text, kind := range map[string]string{
		"osjoin1.eyJ9":            scanJoinBundle,
		"osreq1.abc":              scanEnrollment,
		"OSPB1:ABCDEF":            scanPaperBackup,
		"ospb1:abcdef":            scanPaperBackup,
		"ABCD-EFGH-IJKL-MNOP":     scanFingerprint,
		"abcd efgh ijkl mnop":     scanFingerprint,
		"ABCD-EFGH-IJKL-MNO1":     scanUnknown,
		"https://example.com/x/y": scanUnknown,
		"osinv1.bozuk":            scanUnknown,
		"":                        scanUnknown,
	} {
		var r scanResult
		if err := json.Unmarshal([]byte(ClassifyScan(text)), &r); err != nil || r.Kind != kind {
			t.Errorf("ClassifyScan(%q) = %+v, want %s", text, r, kind)
		}
	}
}

func TestEncodeQRPNGAndDeviceSAS(t *testing.T) {
	secrets, err := GenerateDeviceSecrets()
	if err != nil {
		t.Fatal(err)
	}
	out, err := EnrollmentRequest(secrets, "telefon")
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(out, "\n")
	pngData, err := EncodeQRPNG(line)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		t.Fatal(err)
	}
	// The owner's computer reads it back ("device add --request-image").
	got, err := qr.DecodeImage(img)
	if err != nil || string(got) != line {
		t.Fatalf("read back %q, %v", got, err)
	}
	sas, err := DeviceSAS(secrets)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := trust.DecodeEnrollment(line)
	req, err := trust.OpenEnrollmentRequest(env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sas != req.SAS() {
		t.Fatalf("device SAS %s, owner sees %s", sas, req.SAS())
	}
	if _, err := EncodeQRPNG(""); err == nil {
		t.Fatal("empty text encoded")
	}
	if _, err := EncodeQRPNG(strings.Repeat("x", qr.MaxInput+1)); err == nil {
		t.Fatal("oversized text encoded")
	}
}

// publish signs the owner's current document into the phone's store.
func publish(t *testing.T, tn testNet) {
	t.Helper()
	data, err := tn.net.SignedDocument()
	if err != nil {
		t.Fatal(err)
	}
	store, err := member.Open(tn.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept(data, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func revocation(t *testing.T, tn testNet) revocationStatus {
	t.Helper()
	out, err := RevocationStatus(tn.dir, tn.secrets)
	if err != nil {
		t.Fatal(err)
	}
	var st revocationStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRevocationStatus(t *testing.T) {
	tn := newJoinedPhone(t)
	if st := revocation(t, tn); st.Revoked || !st.Member {
		t.Fatalf("fresh member: %+v", st)
	}
	// Another device revoked: this phone keeps its keys.
	if _, err := tn.net.Apply(testPass, time.Now(), func(doc *trust.Document) error {
		_, err := doc.RevokeDevice("laptop", time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	publish(t, tn)
	if st := revocation(t, tn); st.Revoked || !st.Member {
		t.Fatalf("after another revocation: %+v", st)
	}
	// This phone revoked (lost): wipe.
	if _, err := tn.net.Apply(testPass, time.Now(), func(doc *trust.Document) error {
		_, err := doc.RevokeDevice("telefon", time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	publish(t, tn)
	st := revocation(t, tn)
	if !st.Revoked || st.Member || st.RevokedAt.IsZero() {
		t.Fatalf("after own revocation: %+v", st)
	}
	// A device that was never added is not "revoked".
	other, _ := GenerateDeviceSecrets()
	out, err := RevocationStatus(tn.dir, other)
	if err != nil || !strings.Contains(out, `"revoked":false`) {
		t.Fatalf("unknown device: %s %v", out, err)
	}
	if _, err := RevocationStatus("relative", tn.secrets); err == nil {
		t.Fatal("relative state dir accepted")
	}
}

func TestNetworkPolicy(t *testing.T) {
	policy := `{"rules":[
		{"network":"wifi","ssid":"Ev","exit_node":""},
		{"network":"wifi","exit_node":"home"},
		{"network":"cellular","exit_node":""}
	]}`
	for _, tc := range []struct{ network, ssid, fallback, want string }{
		{"wifi", `"Ev"`, "x", ""},
		{"wifi", "Ev", "x", ""},
		{"wifi", "Kafe", "x", "home"},
		{"wifi", "<unknown ssid>", "x", "home"},
		{"wifi", "", "x", "home"},
		{"cellular", "", "home", ""},
		{"ethernet", "", "home", "home"},
		{"vpn", "", " home ", "home"},
	} {
		got, err := ExitNodeForNetwork(policy, tc.network, tc.ssid, tc.fallback)
		if err != nil || got != tc.want {
			t.Errorf("%s/%q: %q, %v; want %q", tc.network, tc.ssid, got, err, tc.want)
		}
	}
	if got, err := ExitNodeForNetwork("", "wifi", "Ev", "home"); err != nil || got != "home" {
		t.Fatalf("empty policy: %q %v", got, err)
	}
	for _, bad := range []string{
		`{"rules":[{"network":"5g","exit_node":""}]}`,
		`{"rules":[{"network":"cellular","ssid":"Ev","exit_node":""}]}`,
		`{"rules":[{"network":"wifi","ssid":"` + strings.Repeat("a", 33) + `","exit_node":""}]}`,
		`{"rules":[{"network":"wifi","exit":"home"}]}`,
		`{"kurallar":[]}`,
		`{`,
	} {
		if _, err := ExitNodeForNetwork(bad, "wifi", "", ""); err == nil {
			t.Errorf("policy %s accepted", bad)
		}
	}

	tn := newJoinedPhone(t)
	out, err := CheckNetworkPolicy(tn.dir, policy+"")
	if err != nil {
		t.Fatal(err)
	}
	var warnings []string
	if err := json.Unmarshal([]byte(out), &warnings); err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "kural 1") {
		t.Fatalf("warnings %q %v", out, err)
	}
	if _, err := CheckNetworkPolicy(tn.dir, `{"rules":[{"network":"any","exit_node":"laptop"}]}`); err == nil {
		t.Fatal("a device without the exit node role accepted")
	}
	out, err = CheckNetworkPolicy(tn.dir, `{"rules":[{"network":"any","exit_node":"home"},{"network":"wifi","exit_node":""}]}`)
	if err != nil || !strings.Contains(out, "kural 2 hiç uygulanmaz") {
		t.Fatalf("shadowed rule: %s %v", out, err)
	}
	// Without a joined state the names are not checked.
	if _, err := CheckNetworkPolicy(filepath.Join(t.TempDir(), "yok"), `{"rules":[{"network":"any","exit_node":"herhangi"}]}`); err != nil {
		t.Fatal(err)
	}
}

type recordObserver struct {
	waiting []string
	logs    int
}

func (r *recordObserver) Waiting(code, sas string) { r.waiting = append(r.waiting, code+"/"+sas) }
func (r *recordObserver) Log(int, string)          { r.logs++ }

func TestInviteJoinValidation(t *testing.T) {
	if _, err := NewInviteJoin("relative", &recordObserver{}); err == nil {
		t.Fatal("relative dir accepted")
	}
	if _, err := NewInviteJoin(filepath.Join(t.TempDir(), "x"), nil); err == nil {
		t.Fatal("nil observer accepted")
	}
	tn := newJoinedPhone(t)
	created, err := tn.net.CreateInviteWith(testPass, time.Now(), admin.InviteRequest{Life: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	j, _ := NewInviteJoin(tn.dir, &recordObserver{})
	if _, err := j.Run(tn.secrets, created.Code, "telefon"); err == nil || !strings.Contains(err.Error(), "zaten") {
		t.Fatalf("joined dir: %v", err)
	}
	fresh := filepath.Join(t.TempDir(), "openscale")
	j, _ = NewInviteJoin(fresh, &recordObserver{})
	if _, err := j.Run(tn.secrets, "osinv1.bozuk", "telefon"); err == nil {
		t.Fatal("damaged code accepted")
	}
	if _, err := j.Run(tn.secrets, created.Code, strings.Repeat("a", maxHostname+1)); err == nil {
		t.Fatal("long hostname accepted")
	}
	j.Cancel()
	if _, err := j.Run(tn.secrets, created.Code, "telefon"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled join: %v", err)
	}
	if IsJoined(fresh) {
		t.Fatal("a failed join left a joined state")
	}
}
