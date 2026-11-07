package admin

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func TestUpgradeKDF(t *testing.T) {
	n := newNetwork(t)
	stronger := trust.Argon2Params{Time: 2, MemoryKiB: 64 * 1024, Threads: 1}
	got, err := n.UpgradeKDF(testPass, stronger)
	if err != nil || got != stronger {
		t.Fatalf("upgrade %+v %v", got, err)
	}
	if _, err := n.UpgradeKDF(testPass, stronger); !errors.Is(err, ErrKDFCurrent) {
		t.Fatalf("second upgrade: %v", err)
	}
	if _, err := n.UpgradeKDF([]byte("yanlış parola 12345"), trust.Argon2Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// Reloading with weaker options keeps the stronger parameters for later
	// re-sealing, so a passphrase change cannot downgrade the key.
	loaded, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KDFParams() != stronger {
		t.Fatalf("loaded %+v", loaded.KDFParams())
	}
	newPass := []byte("bambaşka bir kök parola 4")
	if err := loaded.ChangePassphrase(testPass, newPass); err != nil {
		t.Fatal(err)
	}
	if loaded.KDFParams().WeakerThan(stronger) {
		t.Fatalf("passphrase change downgraded the KDF to %+v", loaded.KDFParams())
	}
}

func TestKDFCalibrationSwitch(t *testing.T) {
	if got := calibratedArgon2(testOpts.Argon2); got != testOpts.Argon2 {
		t.Fatalf("calibration must be off by default: %+v", got)
	}
	SetKDFCalibration(time.Nanosecond)
	defer SetKDFCalibration(0)
	if got := calibratedArgon2(testOpts.Argon2); got.WeakerThan(trust.DefaultArgon2) {
		t.Fatalf("calibrated %+v is below the default", got)
	}
}

func TestSASConfirmation(t *testing.T) {
	n := newNetwork(t)
	line, _ := requestLine(t)
	pending, err := n.InspectRequest(line, testNow)
	if err != nil {
		t.Fatal(err)
	}
	code := pending.SAS()
	if err := pending.ConfirmSAS(strings.ReplaceAll(code, "-", " ")); err != nil {
		t.Fatal(err)
	}
	if err := pending.ConfirmSAS("0000-0000-0000-0000-0000"); !errors.Is(err, ErrSASMismatch) && code != "0000-0000-0000-0000-0000" {
		t.Fatalf("mismatch: %v", err)
	}
	if n.RootSAS() == code || len(trust.NormalizeSAS(n.RootSAS())) != trust.SASDigits {
		t.Fatalf("root code %q", n.RootSAS())
	}
	if !strings.Contains(Describe(ErrSASMismatch), "eşleşmiyor") {
		t.Fatal("Turkish message missing")
	}
}

func TestPaperBackupRestore(t *testing.T) {
	n := newNetwork(t)
	backupPass := []byte("kâğıt yedek parolası 77")
	packed, err := n.CreatePaperBackup(testPass, backupPass, "kasa", testNow)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(trust.PaperLines(packed), "\n")
	if err := RestorePaper(n.Dir(), text, []byte("yanlış yedek parolası"), testOpts); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := RestorePaper(n.Dir(), trust.PaperQRText(packed), backupPass, testOpts); err != nil {
		t.Fatal(err)
	}
	restored, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.CheckPassphrase(backupPass); err != nil {
		t.Fatalf("restored key must open with the backup passphrase: %v", err)
	}
	// A paper backup of another network is refused.
	other := newNetwork(t)
	foreign, err := other.CreatePaperBackup(testPass, backupPass, "", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestorePaper(n.Dir(), trust.PaperQRText(foreign), backupPass, testOpts); !errors.Is(err, ErrBackupKeyMismatch) {
		t.Fatalf("foreign backup: %v", err)
	}
}

func TestGuessablePassphraseMessage(t *testing.T) {
	err := trust.CheckPassphrase([]byte("password1234"))
	if !strings.Contains(Describe(err), "kolay tahmin") {
		t.Fatalf("message %q", Describe(err))
	}
}
