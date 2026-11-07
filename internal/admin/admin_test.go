package admin

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

var (
	testNow  = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	testPass = []byte("doğru at pil zımba 9")
	testOpts = Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
)

func newNetwork(t *testing.T) *Network {
	t.Helper()
	n, err := Init(t.TempDir(), InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, testPass, testOpts, testNow)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return n
}

func requestLine(t *testing.T) (string, string) {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	env, req, err := s.NewEnrollmentRequest("pc", testNow)
	if err != nil {
		t.Fatal(err)
	}
	line, err := trust.EncodeEnrollment(env)
	if err != nil {
		t.Fatal(err)
	}
	return line, req.Fingerprint()
}

func addDevice(t *testing.T, n *Network, name string) {
	t.Helper()
	line, fp := requestLine(t)
	pending, err := n.InspectRequest(line, testNow)
	if err != nil {
		t.Fatalf("InspectRequest: %v", err)
	}
	if err := pending.ConfirmFingerprint(fp); err != nil {
		t.Fatal(err)
	}
	plan, err := n.Prepare(testNow, trust.DefaultValidity, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, name, nil, testNow, trust.DefaultDeviceLife)
		return err
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func TestPrepareIsDryRun(t *testing.T) {
	n := newNetwork(t)
	line, _ := requestLine(t)
	pending, err := n.InspectRequest(line, testNow)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := n.Prepare(testNow, trust.DefaultValidity, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, "laptop", nil, testNow, trust.DefaultDeviceLife)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Diff.AddedDevices) != 1 || plan.Diff.AddedDevices[0] != "laptop" || plan.Diff.ToVersion != 2 {
		t.Fatalf("unexpected diff: %+v", plan.Diff)
	}
	doc, _ := n.Document()
	if doc.Version != 1 || len(doc.Devices) != 0 {
		t.Fatal("Prepare must not change the current document")
	}
	reloaded, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := reloaded.Document(); d.Version != 1 {
		t.Fatal("Prepare must not write to disk")
	}
}

func TestCommitDetectsConcurrentChange(t *testing.T) {
	n := newNetwork(t)
	other, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	renew := func(doc *trust.Document) error { return nil }
	stale, err := n.Prepare(testNow, trust.DefaultValidity, renew)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := other.Prepare(testNow, trust.DefaultValidity, renew)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Commit(fresh, testPass); err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(stale, testPass); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("stale commit error = %v, want ErrConcurrentChange", err)
	}
	if err := n.Commit(stale, testPass); !errors.Is(err, ErrConcurrentChange) {
		t.Fatal("stale plan must stay rejected after reload")
	}
}

func TestWrongPassphraseDoesNotWrite(t *testing.T) {
	n := newNetwork(t)
	plan, _ := n.Prepare(testNow, trust.DefaultValidity, func(*trust.Document) error { return nil })
	if err := n.Commit(plan, []byte("yanlış parola 12345")); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("error = %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(n.Dir(), historyDir))
	if len(entries) != 1 {
		t.Fatalf("history has %d entries, want 1", len(entries))
	}
}

func TestDuplicateAndMismatchedRequests(t *testing.T) {
	n := newNetwork(t)
	line, fp := requestLine(t)
	pending, err := n.InspectRequest(line, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.ConfirmFingerprint("AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("mismatch error = %v", err)
	}
	if err := pending.ConfirmFingerprint(""); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatal("empty fingerprint must not match")
	}
	if err := pending.ConfirmFingerprint(strings.ToLower(fp)); err != nil {
		t.Fatalf("lowercase fingerprint should match: %v", err)
	}
	plan, _ := n.Prepare(testNow, trust.DefaultValidity, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, "pc", nil, testNow, trust.DefaultDeviceLife)
		return err
	})
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := n.InspectRequest(line, testNow); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("reused request error = %v, want ErrDuplicateRequest", err)
	}
}

func TestChangePassphraseAndBackupRestore(t *testing.T) {
	n := newNetwork(t)
	newPass := []byte("yepyeni uzun parola 7")
	if err := n.ChangePassphrase(testPass, testPass); !errors.Is(err, ErrSamePassphrase) {
		t.Fatalf("same passphrase error = %v", err)
	}
	if err := n.ChangePassphrase(testPass, newPass); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	plan, _ := n.Prepare(testNow, trust.DefaultValidity, func(*trust.Document) error { return nil })
	if err := n.Commit(plan, testPass); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatal("old passphrase must stop working")
	}
	if err := n.Commit(plan, newPass); err != nil {
		t.Fatalf("new passphrase: %v", err)
	}

	backupPass := []byte("yedek kopya parolası 3")
	backup, err := n.CreateBackup(newPass, backupPass, "usb", testNow)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	records, err := n.Backups()
	if err != nil || len(records) != 1 || records[0].Label != "usb" {
		t.Fatalf("backup records = %+v, %v", records, err)
	}

	// Lose the root key, then restore from the backup.
	if err := os.Remove(filepath.Join(n.Dir(), rootKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := Restore(n.Dir(), backup, []byte("yanlış yedek parolası"), testOpts); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("restore with wrong passphrase error = %v", err)
	}
	if err := Restore(n.Dir(), backup, backupPass, testOpts); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restored, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ = restored.Prepare(testNow, trust.DefaultValidity, func(*trust.Document) error { return nil })
	if err := restored.Commit(plan, backupPass); err != nil {
		t.Fatalf("signing with restored key: %v", err)
	}
}

func TestRestoreRejectsForeignBackup(t *testing.T) {
	a := newNetwork(t)
	b := newNetwork(t)
	foreign, err := b.CreateBackup(testPass, []byte("başka ağın yedeği 1"), "", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(a.Dir(), foreign, []byte("başka ağın yedeği 1"), testOpts); !errors.Is(err, ErrBackupKeyMismatch) {
		t.Fatalf("error = %v, want ErrBackupKeyMismatch", err)
	}
}

func TestVerifyHistory(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	addDevice(t, n, "masaustu")
	report, err := n.VerifyHistory()
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || len(report.Entries) != 3 {
		t.Fatalf("report = %+v", report)
	}
	if d := report.Entries[2].Diff; d == nil || len(d.AddedDevices) != 1 || d.AddedDevices[0] != "masaustu" {
		t.Fatalf("diff of v3 = %+v", report.Entries[2].Diff)
	}

	if err := os.Remove(filepath.Join(n.Dir(), historyDir, historyName(2))); err != nil {
		t.Fatal(err)
	}
	report, err = n.VerifyHistory()
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() {
		t.Fatal("a missing version must be reported")
	}

	if err := os.WriteFile(filepath.Join(n.Dir(), historyDir, historyName(2)), []byte(`{"context":"x","payload":"","signature":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, _ = n.VerifyHistory()
	if report.OK() {
		t.Fatal("a forged version must be reported")
	}
}

func TestInitRefusesExistingNetwork(t *testing.T) {
	n := newNetwork(t)
	_, err := Init(n.Dir(), InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, testPass, testOpts, testNow)
	if !errors.Is(err, ErrNetworkExists) {
		t.Fatalf("error = %v", err)
	}
}

func TestDescribeIsTurkish(t *testing.T) {
	if got := Describe(trust.ErrWrongPassphrase); !strings.Contains(got, "Parola yanlış") {
		t.Fatalf("Describe = %q", got)
	}
}
