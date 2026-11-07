//go:build linux

package sdnotify

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifyOverSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram not available: %v", err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	sent, err := Ready("tünel açık")
	if err != nil || !sent {
		t.Fatalf("Ready = %t, %v", sent, err)
	}
	_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := ln.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "READY=1\nSTATUS=tünel açık" {
		t.Fatalf("datagram = %q", got)
	}
}
