package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
)

// fakeMDNSSystem plays a Linux system with avahi and resolved; nothing real
// is run.
type fakeMDNSSystem struct {
	avahi   map[string]bool
	links   map[string]string
	ran     []string
	failArg string
}

func (f *fakeMDNSSystem) output(_ context.Context, c osnet.Command) ([]byte, error) {
	switch {
	case c.Tool == "systemctl" && len(c.Args) == 2 && c.Args[0] == "is-active":
		if f.avahi[c.Args[1]] {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), errors.New("exit status 3")
	case c.Tool == "resolvectl" && len(c.Args) == 1:
		out := "Global: no\n"
		for _, name := range []string{"eth0", "wlan0"} {
			if v, ok := f.links[name]; ok {
				out += "Link 2 (" + name + "): " + v + "\n"
			}
		}
		return []byte(out), nil
	}
	return nil, errors.New("unexpected " + c.String())
}

func (f *fakeMDNSSystem) run(_ context.Context, c osnet.Command) error {
	f.ran = append(f.ran, c.String())
	if f.failArg != "" && slices.Contains(c.Args, f.failArg) {
		return errors.New("failed")
	}
	switch {
	case c.Tool == "systemctl" && c.Args[0] == "stop":
		f.avahi[c.Args[1]] = false
	case c.Tool == "systemctl" && c.Args[0] == "start":
		f.avahi[c.Args[1]] = true
	case c.Tool == "resolvectl":
		f.links[c.Args[1]] = c.Args[2]
	}
	return nil
}

func newFakeMDNS() *fakeMDNSSystem {
	return &fakeMDNSSystem{
		avahi: map[string]bool{"avahi-daemon.service": true, "avahi-daemon.socket": true},
		links: map[string]string{"eth0": "yes", "wlan0": "no"},
	}
}

func TestHideMDNSAndRestore(t *testing.T) {
	f := newFakeMDNS()
	j := OpenJournal(t.TempDir(), time.Now)
	rn := MDNSRunners{Output: f.output, Run: f.run}
	restore, err := HideMDNS(context.Background(), j, MDNSHideWanted(node.OpsecSettings{DHCPRandomName: true}), rn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.avahi["avahi-daemon.service"] || f.avahi["avahi-daemon.socket"] || f.links["eth0"] != "no" || f.links["wlan0"] != "no" {
		t.Fatalf("not hidden: %+v %+v", f.avahi, f.links)
	}
	pending, _ := j.Pending()
	if len(pending) != 1 || pending[0].Kind != JournalMDNS || pending[0].MDNS == nil || len(pending[0].MDNS.Links) != 1 {
		t.Fatalf("journal %+v", pending)
	}
	if err := restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Only what was on comes back; wlan0 stays off as the owner had it.
	if !f.avahi["avahi-daemon.service"] || !f.avahi["avahi-daemon.socket"] || f.links["eth0"] != "yes" || f.links["wlan0"] != "no" {
		t.Fatalf("not restored: %+v %+v", f.avahi, f.links)
	}
	if pending, _ := j.Pending(); len(pending) != 0 {
		t.Fatalf("journal left %+v", pending)
	}
}

func TestHideMDNSOffDoesNothing(t *testing.T) {
	f := newFakeMDNS()
	j := OpenJournal(t.TempDir(), time.Now)
	restore, err := HideMDNS(context.Background(), j, MDNSHideWanted(node.OpsecSettings{}), MDNSRunners{Output: f.output, Run: f.run}, nil)
	if err != nil || len(f.ran) != 0 {
		t.Fatalf("ran %v err %v", f.ran, err)
	}
	if err := restore(context.Background()); err != nil || len(f.ran) != 0 {
		t.Fatal("restore of nothing ran commands")
	}
	if pending, _ := j.Pending(); len(pending) != 0 {
		t.Fatalf("journal %+v", pending)
	}
}

// A crash after the change: the next start puts the announcements back
// from the journal alone.
func TestHideMDNSRecoveredAfterCrash(t *testing.T) {
	f := newFakeMDNS()
	dir := t.TempDir()
	j := OpenJournal(dir, time.Now)
	if _, err := HideMDNS(context.Background(), j, true, MDNSRunners{Output: f.output, Run: f.run}, nil); err != nil {
		t.Fatal(err)
	}
	var restored *osnet.MDNSState
	undo := JournalUndo{MDNS: func(_ context.Context, s osnet.MDNSState) error { restored = &s; return nil }}
	done, err := OpenJournal(dir, time.Now).Recover(context.Background(), undo, nil)
	if err != nil || !slices.Equal(done, []string{JournalMDNS}) {
		t.Fatalf("recover %v %v", done, err)
	}
	if restored == nil || len(restored.AvahiUnits) != 2 || len(restored.Links) != 1 || restored.Links[0].Interface != "eth0" {
		t.Fatalf("restored %+v", restored)
	}
	if SystemUndo.MDNS == nil {
		t.Fatal("system undo misses mDNS")
	}
}

func TestHideMDNSFailureRestores(t *testing.T) {
	f := newFakeMDNS()
	f.failArg = "avahi-daemon.socket"
	j := OpenJournal(t.TempDir(), time.Now)
	_, err := HideMDNS(context.Background(), j, true, MDNSRunners{Output: f.output, Run: f.run}, nil)
	if err == nil {
		t.Fatal("failure not reported")
	}
	// resolved was put back even though avahi failed.
	if f.links["eth0"] != "yes" {
		t.Fatalf("eth0 left off: %+v (ran %v)", f.links, f.ran)
	}
}
