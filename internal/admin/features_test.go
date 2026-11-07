package admin

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func linesContain(lines []string, sub string) bool {
	return slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, sub) })
}

func TestRenameExtendExpireThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	addDevice(t, n, "masaustu")
	if _, err := n.Apply(testPass, testNow, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"3389"}})
	}); err != nil {
		t.Fatal(err)
	}

	plan, err := n.RenameDevice(testPass, "laptop", "dizustu", testNow)
	if err != nil {
		t.Fatalf("RenameDevice: %v", err)
	}
	lines := plan.Diff.Lines()
	if !linesContain(lines, "ad laptop -> dizustu") || !linesContain(lines, "+ kural dizustu -> masaustu tcp/3389") {
		t.Fatalf("rename diff = %v", lines)
	}
	if _, err := n.RenameDevice(testPass, "dizustu", "masaustu", testNow); !errors.Is(err, trust.ErrNameTaken) {
		t.Fatalf("taken name error = %v", err)
	}
	if _, err := n.RenameDevice(testPass, "dizustu", "coordinator", testNow); !errors.Is(err, trust.ErrNameReserved) {
		t.Fatalf("reserved name error = %v", err)
	}

	later := testNow.Add(24 * time.Hour)
	plan, err = n.ExtendDevice(testPass, "dizustu", 3650*24*time.Hour, later)
	if err != nil {
		t.Fatalf("ExtendDevice: %v", err)
	}
	if !linesContain(plan.Diff.Lines(), "üyelik bitişi") {
		t.Fatalf("extend diff = %v", plan.Diff.Lines())
	}
	if _, err := n.ExtendDevice(testPass, "dizustu", 3651*24*time.Hour, later); !errors.Is(err, trust.ErrInvalidLifetime) {
		t.Fatalf("over-long extension error = %v", err)
	}
	if _, err := n.ExpireDevice(testPass, "dizustu", later); err != nil {
		t.Fatalf("ExpireDevice: %v", err)
	}
	doc, _ := n.Document()
	if d, _ := doc.DeviceByName("dizustu"); !d.ExpiresAt.Equal(later) {
		t.Fatalf("expired at %v", d.ExpiresAt)
	}
	if _, err := n.RenameDevice([]byte("yanlış parola 1234"), "dizustu", "yeni", later); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	if report, err := n.VerifyHistory(); err != nil || !report.OK() {
		t.Fatalf("history: %v %+v", err, report.Problems)
	}
}

func TestKeyRotationThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	secrets, err := trust.GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	env, _, _ := secrets.NewEnrollmentRequest("pc", testNow)
	line, _ := trust.EncodeEnrollment(env)
	pending, err := n.InspectRequest(line, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Apply(testPass, testNow, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, "laptop", nil, testNow, trust.DefaultDeviceLife)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	doc, _ := n.Document()
	_, sr, req, err := secrets.NewKeyRotation(rand.Reader, doc.NetworkID, testNow)
	if err != nil {
		t.Fatal(err)
	}
	rotLine, _ := trust.EncodeKeyRotation(sr)
	pr, err := n.InspectKeyRotation(rotLine, testNow)
	if err != nil {
		t.Fatalf("InspectKeyRotation: %v", err)
	}
	if pr.Device.Name != "laptop" || pr.Fingerprint != req.Fingerprint() {
		t.Fatalf("pending rotation = %+v", pr)
	}
	if _, err := n.ApplyKeyRotation(testPass, rotLine, "AAAA-BBBB-CCCC-DDDD", testNow); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("wrong fingerprint error = %v", err)
	}
	if _, err := n.ApplyKeyRotation(testPass, rotLine, "", testNow); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("empty fingerprint error = %v", err)
	}
	plan, err := n.ApplyKeyRotation(testPass, rotLine, strings.ToLower(req.Fingerprint()), testNow)
	if err != nil {
		t.Fatalf("ApplyKeyRotation: %v", err)
	}
	if !linesContain(plan.Diff.Lines(), "anahtarlar yenilendi") || !linesContain(plan.Diff.Lines(), "emekliye ayrıldı") {
		t.Fatalf("rotation diff = %v", plan.Diff.Lines())
	}
	if _, err := n.ApplyKeyRotation(testPass, rotLine, req.Fingerprint(), testNow); err == nil {
		t.Fatal("a rotation must not apply twice")
	}
	// The old enrollment request is now unusable: its keys are retired.
	if _, err := n.InspectRequest(line, testNow); err == nil {
		t.Fatal("request with retired keys must be rejected")
	}
}

func TestPolicyAndDNSThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	addDevice(t, n, "nas")
	if _, err := n.SetDeviceTags(testPass, "nas", []string{"sunucu"}, testNow); err != nil {
		t.Fatal(err)
	}
	plan, err := n.SetGroup(testPass, "aile", []string{"laptop"}, testNow)
	if err != nil || !linesContain(plan.Diff.Lines(), "+ grup aile [laptop]") {
		t.Fatalf("SetGroup: %v %v", err, plan)
	}
	if _, err := n.Apply(testPass, testNow, func(doc *trust.Document) error {
		if err := doc.AddRule(trust.Rule{From: []string{"group:aile"}, To: []string{"tag:sunucu"}, Protocol: trust.ProtocolAny}); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}, Action: trust.RuleDeny})
	}); err != nil {
		t.Fatal(err)
	}
	plan, err = n.SetRuleDisabled(testPass, 1, true, testNow)
	if err != nil || !linesContain(plan.Diff.Lines(), "+ kural reddet: laptop -> nas tcp/22 (kapalı)") {
		t.Fatalf("SetRuleDisabled: %v %v", err, plan.Diff.Lines())
	}
	plan, err = n.SetExitUsers(testPass, []string{"group:aile"}, testNow)
	if err != nil || !linesContain(plan.Diff.Lines(), "Çıkış düğümü kullanıcıları: herkes -> group:aile") {
		t.Fatalf("SetExitUsers: %v %v", err, plan)
	}
	if _, err := n.ClearExitUsers(testPass, testNow); err != nil {
		t.Fatal(err)
	}
	doc, _ := n.Document()
	nas, _ := doc.DeviceByName("nas")
	plan, err = n.SetDNS(testPass, &trust.DNSSettings{Split: []trust.SplitDNS{{Domain: "ev.lan", Nameservers: []netip.Addr{nas.IPv4}}}}, testNow)
	if err != nil || !linesContain(plan.Diff.Lines(), "ev.lan => "+nas.IPv4.String()) {
		t.Fatalf("SetDNS: %v %v", err, plan)
	}
	if _, err := n.SetDNS(testPass, &trust.DNSSettings{Nameservers: []netip.Addr{netip.MustParseAddr("9.9.9.9")}}, testNow); err == nil {
		t.Fatal("public resolver must be rejected")
	}
	if _, err := n.RemoveGroup(testPass, "aile", testNow); err == nil {
		t.Fatal("group in use must not be removable")
	}
	if report, err := n.VerifyHistory(); err != nil || !report.OK() {
		t.Fatalf("history: %v %+v", err, report.Problems)
	}
}

func TestTaggedInviteApproval(t *testing.T) {
	n := newNetwork(t)
	var coordKey trust.Key
	if _, err := rand.Read(coordKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Apply(testPass, testNow, func(doc *trust.Document) error {
		return doc.SetCoordinator("vpn.example.org:41820", coordKey)
	}); err != nil {
		t.Fatal(err)
	}
	enroll := func(tags []string, opts *ApproveOptions, name string) trust.Device {
		t.Helper()
		created, err := n.CreateTaggedInvite(testPass, testNow, time.Hour, tags)
		if err != nil {
			t.Fatalf("CreateTaggedInvite: %v", err)
		}
		code, err := trust.DecodeInviteCode(created.Code)
		if err != nil {
			t.Fatal(err)
		}
		secrets, _ := trust.GenerateDeviceSecrets(rand.Reader, testNow)
		se, _, err := secrets.NewInviteEnrollment(code, name, testNow)
		if err != nil {
			t.Fatal(err)
		}
		var dev trust.Device
		if opts == nil {
			dev, err = n.ApproveInvite(testPass, se, name, nil, testNow)
		} else {
			dev, err = n.ApproveInviteWith(testPass, se, name, nil, *opts, testNow)
		}
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		return dev
	}
	if d := enroll([]string{"mobil"}, nil, "telefon"); !slices.Equal(d.Tags, []string{"mobil"}) {
		t.Fatalf("device tags = %v, want invite tags", d.Tags)
	}
	if d := enroll([]string{"mobil"}, &ApproveOptions{OverrideTags: true, Tags: []string{"tablet"}}, "tablet"); !slices.Equal(d.Tags, []string{"tablet"}) {
		t.Fatalf("override tags = %v", d.Tags)
	}
	if d := enroll([]string{"mobil"}, &ApproveOptions{OverrideTags: true}, "eski"); len(d.Tags) != 0 {
		t.Fatalf("cleared tags = %v", d.Tags)
	}
	if d := enroll(nil, nil, "pc"); len(d.Tags) != 0 {
		t.Fatalf("untagged invite gave tags %v", d.Tags)
	}
	if _, err := n.CreateTaggedInvite(testPass, testNow, time.Hour, []string{"Kötü"}); err == nil {
		t.Fatal("invalid invite tag must be rejected")
	}
}

func TestDisplayNameThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	plan, err := n.SetDisplayName(testPass, "Ev ağı", testNow)
	if err != nil {
		t.Fatalf("SetDisplayName: %v", err)
	}
	if !linesContain(plan.Diff.Lines(), "Ağ adı: yok -> Ev ağı") {
		t.Fatalf("diff = %v", plan.Diff.Lines())
	}
	if _, err := n.SetDisplayName(testPass, "‮ters", testNow); !errors.Is(err, trust.ErrInvalidDisplayName) {
		t.Fatalf("invalid name error = %v", err)
	}
	if _, err := n.SetDisplayName(testPass, "", testNow); err != nil {
		t.Fatalf("remove: %v", err)
	}
	doc, _ := n.Document()
	if doc.DisplayName != "" {
		t.Fatalf("display name = %q", doc.DisplayName)
	}
	if !strings.Contains(Describe(trust.ErrInvalidDisplayName), "Ağ adı") {
		t.Fatal("missing Turkish message")
	}
}
