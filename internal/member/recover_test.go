package member_test

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

var (
	testPass = []byte("kurtarma test parolası 7")
	testOpts = admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
)

func newNetwork(t *testing.T) *admin.Network {
	t.Helper()
	n, err := admin.Init(filepath.Join(t.TempDir(), "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, testPass, testOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func joinStore(t *testing.T, n *admin.Network) (string, *member.Store) {
	t.Helper()
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "uye")
	st, err := member.Join(dir, bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return dir, st
}

func bump(t *testing.T, n *admin.Network, st *member.Store) {
	t.Helper()
	if _, err := n.Apply(testPass, time.Now(), func(doc *trust.Document) error { return doc.SetDisplayName("Ev ağı") }); err != nil {
		t.Fatal(err)
	}
	data, err := n.SignedDocument()
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := st.Accept(data, time.Now()); err != nil || !changed {
		t.Fatalf("Accept: %v %v", changed, err)
	}
}

func quarantined(t *testing.T, dir, name string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), name+".corrupt-") {
			c++
		}
	}
	return c
}

func TestBackupCopyWritten(t *testing.T) {
	n := newNetwork(t)
	dir, st := joinStore(t, n)
	bump(t, n, st)
	a, err := os.ReadFile(filepath.Join(dir, "network.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "network.json.bak"))
	if err != nil || string(a) != string(b) {
		t.Fatalf("backup copy differs: %v", err)
	}
	re, err := member.Open(dir)
	if err != nil || len(re.Recovered()) != 0 {
		t.Fatalf("clean open: %v %v", err, re.Recovered())
	}
}

func TestCorruptStateRebuiltFromDocument(t *testing.T) {
	n := newNetwork(t)
	dir, st := joinStore(t, n)
	bump(t, n, st)
	want := st.Document().Version
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{bozuk"), 0o600); err != nil {
		t.Fatal(err)
	}
	re, err := member.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if re.Document().Version != want || len(re.Recovered()) == 0 {
		t.Fatalf("version %d, notes %v", re.Document().Version, re.Recovered())
	}
	if quarantined(t, dir, "state.json") != 1 {
		t.Fatal("corrupt state file not quarantined")
	}
	// The rebuilt rollback state still refuses older documents.
	if _, err := member.Open(dir); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptDocumentRestoredFromBackup(t *testing.T) {
	n := newNetwork(t)
	dir, st := joinStore(t, n)
	bump(t, n, st)
	want := st.Document().Version
	if err := os.WriteFile(filepath.Join(dir, "network.json"), []byte("çöp"), 0o600); err != nil {
		t.Fatal(err)
	}
	re, err := member.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if re.Document().Version != want || len(re.Recovered()) == 0 {
		t.Fatalf("version %d, notes %v", re.Document().Version, re.Recovered())
	}
	if quarantined(t, dir, "network.json") != 1 {
		t.Fatal("corrupt document not quarantined")
	}
	again, err := member.Open(dir)
	if err != nil || len(again.Recovered()) != 0 {
		t.Fatalf("second open: %v %v", err, again.Recovered())
	}
}

func TestBothCopiesLostNeedsRepair(t *testing.T) {
	n := newNetwork(t)
	dir, st := joinStore(t, n)
	bump(t, n, st)
	for _, f := range []string{"network.json", "network.json.bak"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := member.Open(dir); !errors.Is(err, member.ErrNeedsDocument) {
		t.Fatalf("Open = %v, want ErrNeedsDocument", err)
	}
	// An older document from a peer is refused: the rollback state survived.
	older, err := os.ReadFile(filepath.Join(n.Dir(), "history", "v0000000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Repair(dir, older, time.Now()); !errors.Is(err, trust.ErrRollback) {
		t.Fatalf("Repair with an older document = %v", err)
	}
	current, err := n.SignedDocument()
	if err != nil {
		t.Fatal(err)
	}
	re, err := member.Repair(dir, current, time.Now())
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if re.Document().Version != st.Document().Version {
		t.Fatal("wrong version after repair")
	}
	if _, err := member.Open(dir); err != nil {
		t.Fatalf("Open after repair: %v", err)
	}
}

func TestDocumentOfAnotherNetworkRefused(t *testing.T) {
	n, other := newNetwork(t), newNetwork(t)
	dir, _ := joinStore(t, n)
	foreign, err := other.SignedDocument()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Repair(dir, foreign, time.Now()); err == nil {
		t.Fatal("document of another network accepted")
	}
}

func TestUnreadableIsNotRepaired(t *testing.T) {
	n := newNetwork(t)
	dir, _ := joinStore(t, n)
	// A directory where a file should be: a read error, not corruption.
	path := filepath.Join(dir, "state.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := member.Open(dir); err == nil {
		t.Fatal("Open succeeded with an unreadable state file")
	}
	if quarantined(t, dir, "state.json") != 0 {
		t.Fatal("unreadable state file was moved")
	}
}

func TestCrashBetweenDocumentAndState(t *testing.T) {
	n := newNetwork(t)
	dir, st := joinStore(t, n)
	bump(t, n, st)
	// The owner signs once more; only network.json reaches the disk before
	// a crash, state.json still names the older version.
	if _, err := n.Apply(testPass, time.Now(), func(doc *trust.Document) error { return doc.SetDisplayName("Ev ağı 2") }); err != nil {
		t.Fatal(err)
	}
	newer, err := n.SignedDocument()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.json"), newer, 0o600); err != nil {
		t.Fatal(err)
	}
	re, err := member.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if re.Document().Version != st.Document().Version+1 || len(re.Recovered()) == 0 {
		t.Fatalf("version %d, notes %v", re.Document().Version, re.Recovered())
	}
	// An older document in network.json with the backup at the state's
	// version: restored from the backup, never accepted as is.
	older, err := os.ReadFile(filepath.Join(n.Dir(), "history", "v0000000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.json"), older, 0o600); err != nil {
		t.Fatal(err)
	}
	re, err = member.Open(dir)
	if err != nil || re.Document().Version != st.Document().Version+1 {
		t.Fatalf("older primary: %v", err)
	}
}
