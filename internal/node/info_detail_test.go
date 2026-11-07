package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/sysinfo"
)

func testInventory(t *testing.T, build string) ([]byte, string) {
	t.Helper()
	d := sysinfo.Detail{Ver: sysinfo.DetailVersion, Users: 1, OS: sysinfo.OSDetail{Name: "Windows 11 Pro", Build: build}}
	for i := range 16 { // incompressible text: several chunks after compression
		h := sha256.Sum256([]byte(build + string(rune(i))))
		x := hex.EncodeToString(h[:])
		d.NICs = append(d.NICs, sysinfo.NIC{Name: x[:40], Model: x[24:]})
		d.Disks = append(d.Disks, sysinfo.Disk{Index: i, Model: x[8:56]})
	}
	blob, id, err := sysinfo.EncodeDetail(d)
	if err != nil {
		t.Fatal(err)
	}
	return blob, id
}

// fakePeer serves chunks of the current blob like detailChunkReply does.
type fakePeer struct {
	blobs map[string][]byte
	cur   string
	calls int
	// change switches cur after this many calls (0: never).
	change int
	next   string
}

func (p *fakePeer) call(_ context.Context, m control.Message) (control.Message, error) {
	p.calls++
	if p.change > 0 && p.calls == p.change {
		p.cur = p.next
	}
	if m.T != control.TypeInfoDetail {
		return control.Message{}, errors.New("unexpected type")
	}
	blob, id, off := p.blobs[p.cur], p.cur, m.Offset
	if m.Digest != id {
		off = 0
	}
	end := min(off+control.ChunkSize, len(blob))
	resp := control.Message{T: control.TypeInfoDetail, Offset: off, Total: len(blob), Digest: id, Data: blob[off:end]}
	// The reply must fit the control protocol's datagram.
	if _, err := control.Encode(resp); err != nil {
		return control.Message{}, err
	}
	return resp, nil
}

func TestFetchDetailChunksAndRestart(t *testing.T) {
	b1, id1 := testInventory(t, "26300.1")
	b2, id2 := testInventory(t, "26300.2")
	if len(b1) <= control.ChunkSize {
		t.Fatalf("test inventory fits one chunk (%d bytes)", len(b1))
	}
	p := &fakePeer{blobs: map[string][]byte{id1: b1, id2: b2}, cur: id1}
	d, id, err := fetchDetail(context.Background(), id1, p.call)
	if err != nil || id != id1 || d.OS.Build != "26300.1" {
		t.Fatalf("fetch: %v %q %+v", err, id, d)
	}
	// The peer's inventory changes in the middle of a fetch: start over
	// with the new identifier.
	p = &fakePeer{blobs: map[string][]byte{id1: b1, id2: b2}, cur: id1, change: 2, next: id2}
	d, id, err = fetchDetail(context.Background(), id1, p.call)
	if err != nil || id != id2 || d.OS.Build != "26300.2" {
		t.Fatalf("restart: %v %q", err, id)
	}
	// A peer that lies about the identifier or the offsets is refused.
	bad := func(_ context.Context, m control.Message) (control.Message, error) {
		return control.Message{T: control.TypeInfoDetail, Offset: m.Offset + 1, Total: len(b1), Digest: id1, Data: b1[:10]}, nil
	}
	if _, _, err := fetchDetail(context.Background(), id1, bad); err == nil {
		t.Fatal("bad offset accepted")
	}
	wrong := func(_ context.Context, m control.Message) (control.Message, error) {
		return control.Message{T: control.TypeInfoDetail, Total: len(b2), Digest: id1, Data: b2[m.Offset:min(m.Offset+control.ChunkSize, len(b2))], Offset: m.Offset}, nil
	}
	if _, _, err := fetchDetail(context.Background(), id1, wrong); err == nil {
		t.Fatal("content not matching its identifier accepted")
	}
}

func TestAttachDetailUsesCache(t *testing.T) {
	b1, id1 := testInventory(t, "26300.3")
	p := &fakePeer{blobs: map[string][]byte{id1: b1}, cur: id1}
	e := &Engine{cfg: Config{Now: func() time.Time { return time.Unix(1700000000, 0) }}}
	in := sysinfo.Info{DetailVer: sysinfo.DetailVersion, DetailID: id1}
	e.attachDetail(context.Background(), &in, "test/cache", p.call)
	first := p.calls
	if in.Detail == nil || first == 0 {
		t.Fatalf("not fetched: %+v", in)
	}
	in2 := sysinfo.Info{DetailVer: sysinfo.DetailVersion, DetailID: id1}
	e.attachDetail(context.Background(), &in2, "test/cache", p.call)
	if p.calls != first || in2.Detail == nil {
		t.Fatalf("unchanged inventory fetched again (%d calls)", p.calls)
	}
	// An unknown version or no announcement: nothing is fetched.
	in3 := sysinfo.Info{DetailVer: sysinfo.DetailVersion + 1, DetailID: id1}
	e.attachDetail(context.Background(), &in3, "test/other", p.call)
	if in3.Detail != nil || p.calls != first {
		t.Fatal("inventory of an unknown version fetched")
	}
	// A failing peer keeps the last known inventory.
	failing := func(context.Context, control.Message) (control.Message, error) {
		return control.Message{}, errors.New("timeout")
	}
	in4 := sysinfo.Info{DetailVer: sysinfo.DetailVersion, DetailID: strings.Repeat("b", 24)}
	e.attachDetail(context.Background(), &in4, "test/cache", failing)
	if in4.Detail == nil || in4.Detail.OS.Build != "26300.3" {
		t.Fatal("last known inventory dropped on failure")
	}
}

func TestDetailRateLimit(t *testing.T) {
	now := time.Unix(1700000000, 0)
	src := netip.MustParseAddr("100.64.0.9")
	n := 0
	for range detailBudget + 5 {
		if allowDetail(src, now) {
			n++
		}
	}
	if n != detailBudget || !allowDetail(src, now.Add(detailWindow+time.Second)) {
		t.Fatalf("allowed %d", n)
	}
}
