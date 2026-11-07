package node

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/trust"
)

// The owner rotates the root key in the network directory; the watching
// laptop adopts it with transitions.json, hands the transition to the
// coordinator and uploads the new document; the other device follows
// without joining again (ADR-0027). A version minimum then keeps working
// because new clients report their version (F-027).
func TestRootRotationReachesDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t), NetworkDir: filepath.Join(tn.base, "ag")})
	b, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t)})
	waitFor(t, 10*time.Second, "masaustu syncs once", func() bool { return !b.Status().LastSync.IsZero() && b.Status().LastSyncError == "" })

	if _, err := tn.n.RotateRoot(e2ePass, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "laptop adopts the new root", func() bool { return aStore.Epoch() == 1 })
	waitFor(t, 20*time.Second, "masaustu follows the new root", func() bool { return bStore.Epoch() == 1 })
	if bStore.Document().RootEpoch != 1 {
		t.Fatal("masaustu document not at the new epoch")
	}
	// Normal edits after the rotation still reach masaustu.
	before := bStore.Document().Version
	commit(t, tn.n, func(doc *trust.Document) error { return doc.SetMinClientVersion("0.0.0") })
	waitFor(t, 20*time.Second, "masaustu adopts the next version", func() bool {
		return bStore.Document().Version > before && b.Status().LastSyncError == ""
	})
}

func TestMachineBinding(t *testing.T) {
	if _, ok := machineID(); !ok || machineBindingDisabled() {
		t.Skip("no machine id on this system")
	}
	dir := t.TempDir()
	id := "0123456789abcdef0123456789abcdef"
	if err := CheckMachineBinding(dir, id); err != nil {
		t.Fatal(err)
	}
	if err := CheckMachineBinding(dir, id); err != nil {
		t.Fatalf("same machine refused: %v", err)
	}
	// A binding made on another computer is refused.
	if err := writeBinding(filepath.Join(dir, machineBindingFile), bindingDigest("another-machine-id", id)); err != nil {
		t.Fatal(err)
	}
	if err := CheckMachineBinding(dir, id); err != ErrMachineChanged {
		t.Fatalf("copied identity accepted: %v", err)
	}
	t.Setenv("OPENSCALE_ALLOW_MACHINE_CHANGE", "1")
	if err := CheckMachineBinding(dir, id); err != nil {
		t.Fatalf("allowed move refused: %v", err)
	}
	os.Unsetenv("OPENSCALE_ALLOW_MACHINE_CHANGE")
	if err := RebindMachine(dir, id); err != nil {
		t.Fatal(err)
	}
	if err := CheckMachineBinding(dir, id); err != nil {
		t.Fatal(err)
	}
}
