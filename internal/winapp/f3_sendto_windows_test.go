//go:build windows

package winapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSendToPipe runs the tray side and the Send to side in one process:
// the files are opened while impersonating the caller and arrive open.
func TestSendToPipe(t *testing.T) {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	old := sendToPipePrefix
	sendToPipePrefix = `\\.\pipe\openscale-sendto-test-` + hex.EncodeToString(rnd[:]) + "-"
	t.Cleanup(func() { sendToPipePrefix = old })

	if err := SendToTray([]string{`C:\x`}); !errors.Is(err, ErrSendToTrayMissing) {
		t.Fatalf("without a tray: %v", err)
	}

	dir := t.TempDir()
	a := filepath.Join(dir, "rapor.txt")
	if err := os.WriteFile(a, []byte("içerik"), 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.txt")
	if err := os.Link(a, hard); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	b := filepath.Join(dir, "tek.txt")
	if err := os.WriteFile(b, []byte("tek"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan []SendToFile, 1)
	served := make(chan error, 1)
	go func() { served <- ServeSendTo(ctx, func(f []SendToFile) { got <- f }) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("ServeSendTo did not stop")
		}
	})
	// Wait for the pipe.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := SendToTray([]string{b})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrSendToTrayMissing) || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case files := <-got:
		if len(files) != 1 || files[0].Name != "tek.txt" || files[0].Size != 3 {
			t.Fatalf("files %+v", files)
		}
		data, err := io.ReadAll(files[0].File)
		files[0].File.Close()
		if err != nil || string(data) != "tek" {
			t.Fatalf("read %q, %v", data, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler not called")
	}

	// A file with two names is refused on the open handle.
	if err := SendToTray([]string{hard}); err == nil {
		t.Fatal("hard-linked file accepted")
	}
	// A folder is refused before anything is opened.
	if err := SendToTray([]string{dir}); err == nil {
		t.Fatal("folder accepted")
	}
}
