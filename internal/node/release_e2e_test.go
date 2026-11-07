package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
)

// The coordinator's release mirror (ADR-0225) is reachable inside the
// tunnel: the announcement, then the file in chunks bound to it. Only
// 127.0.0.1 is used.
func TestReleaseMirrorThroughTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	mirror := filepath.Join(t.TempDir(), coordinator.ReleaseMirrorDir)
	if err := os.MkdirAll(mirror, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"format":"not verified by the coordinator"}`)
	prog := bytes.Repeat([]byte("openscale"), 300) // several chunks
	for name, data := range map[string][]byte{"openscale-1.2.3.release.json": manifest, "openscale-linux-amd64.gz": prog, "notes.txt": []byte("x")} {
		if err := os.WriteFile(filepath.Join(mirror, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := coordinator.New(coordinator.Config{Store: tn.join(t, "koordinator"), Secrets: tn.coordSecrets, ListenPort: tn.coordPort,
		Logger: testLogger(t, "[koordinatör]"), ReleaseMirror: mirror})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Run(ctx) }()
	<-c.Ready()
	e, _ := startEngine(ctx, t, Config{Store: tn.join(t, "laptop"), Secrets: tn.aKey, TUN: tuntest.NewChannelTUN().TUN(), ListenPort: freeUDPPort(t)})

	var ann control.Message
	waitFor(t, 10*time.Second, "release announcement", func() bool {
		ann, err = e.ReleaseCall(ctx, control.Message{T: control.TypeRelease})
		return err == nil
	})
	sum := sha256.Sum256(manifest)
	if ann.Release != "1.2.3" || ann.File != "openscale-1.2.3.release.json" || ann.Digest != hex.EncodeToString(sum[:]) || ann.Size != len(manifest) {
		t.Fatalf("announcement %+v", ann)
	}
	var got []byte
	for off := 0; ; {
		resp, err := e.ReleaseCall(ctx, control.Message{T: control.TypeReleaseFile, File: "openscale-linux-amd64.gz", Digest: ann.Digest, Offset: off})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, resp.Data...)
		off += len(resp.Data)
		if off >= resp.Total {
			break
		}
	}
	if !bytes.Equal(got, prog) {
		t.Fatal("file differs")
	}
	// Unlisted names, other publications and other message types are refused.
	if _, err := e.ReleaseCall(ctx, control.Message{T: control.TypeReleaseFile, File: "notes.txt", Digest: ann.Digest}); err == nil {
		t.Fatal("unlisted file served")
	}
	if _, err := e.ReleaseCall(ctx, control.Message{T: control.TypeReleaseFile, File: "openscale-linux-amd64.gz", Digest: string(bytes.Repeat([]byte("0"), 64))}); err == nil {
		t.Fatal("chunk of another publication served")
	}
	if _, err := e.ReleaseCall(ctx, control.Message{T: control.TypeHello}); err == nil {
		t.Fatal("ReleaseCall sent a non-release request")
	}
}
