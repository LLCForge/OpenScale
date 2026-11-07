package filesend

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Regression tests for the F2 finding: the classic receive path labelled
// files only on Windows. 127.0.0.1 only.

// startMarkServer runs a server whose mark function is mark.
func startMarkServer(t *testing.T, mark func(path, origin string) error) (netip.AddrPort, string, chan Received) {
	t.Helper()
	inbox := filepath.Join(t.TempDir(), "inbox")
	got := make(chan Received, 1)
	srv, err := NewServer(Config{
		InboxDir:   inbox,
		Accept:     func(netip.Addr, string, int64) bool { return true },
		OnReceived: func(r Received) { got <- r },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.mark = mark
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().(*net.TCPAddr).AddrPort(), inbox, got
}

// TestClassicReceiveMarksQuarantine: a file received on the classic path
// goes through the cross-platform mark with the sender as origin, and on a
// file system that can store the mark the operating system sees it.
func TestClassicReceiveMarksQuarantine(t *testing.T) {
	var marked, origin string
	addr, inbox, got := startMarkServer(t, func(path, o string) error {
		marked, origin = path, o
		return MarkQuarantine(path, o)
	})
	if _, err := Send(ctx(t), addr, writeTemp(t, "kurulum.sh", []byte("#!/bin/sh\n")), nil); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if marked != r.Path {
		t.Fatalf("mark called for %q, received %q", marked, r.Path)
	}
	if origin != "openscale:127.0.0.1" {
		t.Fatalf("origin = %q", origin)
	}
	probe := filepath.Join(inbox, "isaret-denemesi")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkQuarantine(probe, "openscale:deneme"); err != nil {
		// tmpfs and some file systems refuse the mark; the result must say so.
		if r.Quarantined {
			t.Fatal("unmarked file reported as quarantined")
		}
		t.Skipf("file system cannot store the mark: %v", err)
	}
	if !r.Quarantined || !IsQuarantined(r.Path) {
		t.Fatalf("received file not marked: reported %v, on disk %v", r.Quarantined, IsQuarantined(r.Path))
	}
}

// TestClassicReceiveReportsUnmarkedFile: a failed mark does not lose the
// file, and the receiver is told it is unmarked.
func TestClassicReceiveReportsUnmarkedFile(t *testing.T) {
	addr, _, got := startMarkServer(t, func(string, string) error { return ErrQuarantineUnsupported })
	if _, err := Send(ctx(t), addr, writeTemp(t, "a.txt", []byte("x")), nil); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.Quarantined {
		t.Fatal("failed mark reported as quarantined")
	}
	if b, err := os.ReadFile(r.Path); err != nil || string(b) != "x" {
		t.Fatalf("file lost: %q %v", b, err)
	}
}
