package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

func TestInviteJoinWithApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordSecrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := coordSecrets.PublicKeys()
	coordPort := freeUDPPort(t)
	commit(t, n, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(coordPort), coordWG)
	})

	// The owner's management device has the admin role.
	adminKey, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := adminKey.NewEnrollmentRequest("yonetim", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, err := trust.OpenEnrollmentRequest(env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commit(t, n, func(doc *trust.Document) error {
		_, err := doc.AddDevice(req, "yonetim", []trust.Role{trust.RoleAdmin}, time.Now(), trust.DefaultDeviceLife)
		return err
	})
	plainKey := enroll(t, n, "sade")

	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	adminStore := join(t, n, filepath.Join(base, "yonetim"))
	plainStore := join(t, n, filepath.Join(base, "sade"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	select {
	case <-coord.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not start")
	}

	start := func(store *member.Store, secrets *trust.DeviceSecrets, networkDir string) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: tuntest.NewChannelTUN().TUN(), NetworkDir: networkDir,
			PollInterval: 300 * time.Millisecond, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = e.Run(ctx) }()
		return e
	}
	adminEngine := start(adminStore, adminKey, netDir)
	plainEngine := start(plainStore, plainKey, "")

	created, err := n.CreateInvite(e2ePass, time.Now(), trust.DefaultInviteLife)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	code, err := trust.DecodeInviteCode(created.Code)
	if err != nil {
		t.Fatal(err)
	}

	newKey, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan string, 1)
	joined := make(chan *member.Store, 1)
	joinErr := make(chan error, 1)
	go func() {
		st, err := JoinWithInvite(ctx, InviteJoinConfig{
			Code: code, Secrets: newKey, Hostname: "Yeni-PC", StateDir: filepath.Join(base, "yeni"),
			PollInterval: 200 * time.Millisecond, Logger: testLogger(t, "[yeni]"),
			OnWaiting: func(r *trust.EnrollmentRequest) { waiting <- r.ShortCode() },
		})
		if err != nil {
			joinErr <- err
			return
		}
		joined <- st
	}()

	var shown string
	select {
	case shown = <-waiting:
	case err := <-joinErr:
		t.Fatalf("JoinWithInvite: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("enrollment never reached the coordinator")
	}

	// A device without the admin role is refused.
	if _, err := plainEngine.Pending(ctx); err == nil {
		t.Fatal("non-admin device listed pending enrollments")
	}

	// The admin reads system reports from another device and from the
	// coordinator through the tunnel; a plain device cannot.
	plainSelf, _ := plainEngine.Self()
	adminSelf, _ := adminEngine.Self()
	var report sysinfoReport
	deadline0 := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline0) {
		qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
		in, err := adminEngine.QueryInfo(qctx, plainSelf.IPv4)
		qcancel()
		if err == nil {
			report = sysinfoReport{os: in.OS, cores: in.Cores}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if report.os == "" || report.cores < 1 {
		t.Fatal("admin could not read the device report")
	}
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	if in, err := adminEngine.CoordinatorInfo(cctx); err != nil || in.OS == "" {
		t.Fatalf("coordinator report: %v", err)
	}
	ccancel()
	// The detailed inventory (ADR-0143) follows the base report in chunks
	// once the background collection finished, from the device and from
	// the coordinator.
	gotDevice, gotCoord := false, false
	for deadline1 := time.Now().Add(30 * time.Second); time.Now().Before(deadline1) && !(gotDevice && gotCoord); {
		qctx, qcancel := context.WithTimeout(ctx, 4*time.Second)
		if in, err := adminEngine.QueryInfo(qctx, plainSelf.IPv4); err == nil && in.Detail != nil && in.Detail.CPU.Threads > 0 {
			gotDevice = true
		}
		if in, err := adminEngine.CoordinatorInfo(qctx); err == nil && in.Detail != nil && in.Detail.CPU.Threads > 0 {
			gotCoord = true
		}
		qcancel()
		time.Sleep(300 * time.Millisecond)
	}
	if !gotDevice || !gotCoord {
		t.Fatalf("detailed inventory not fetched: device %v, coordinator %v", gotDevice, gotCoord)
	}
	pctx, pcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	if _, err := plainEngine.QueryInfo(pctx, adminSelf.IPv4); err == nil {
		t.Fatal("plain device read the admin's report")
	}
	pcancel()
	pctx, pcancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	if _, err := plainEngine.CoordinatorInfo(pctx); err == nil {
		t.Fatal("plain device read the coordinator report")
	}
	pcancel()

	var pending []admin.PendingInvite
	deadline := time.Now().Add(10 * time.Second)
	for len(pending) == 0 && time.Now().Before(deadline) {
		list, err := adminEngine.Pending(ctx)
		if err == nil {
			pending = n.VerifyPending(list, time.Now())
		}
		if len(pending) == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending enrollments", len(pending))
	}
	p := pending[0]
	if !trust.SameShortCode(p.ShortCode, shown) || p.Request.Hostname != "yeni-pc" || p.InviteID != created.Invite.ID {
		t.Fatalf("pending enrollment differs: code %s vs %s", p.ShortCode, shown)
	}

	dev, err := n.ApproveInvite(e2ePass, p.Signed, "yeni-pc", nil, time.Now())
	if err != nil {
		t.Fatalf("ApproveInvite: %v", err)
	}
	select {
	case st := <-joined:
		if _, ok := st.Document().DeviceByName(dev.Name); !ok {
			t.Fatal("joined store does not list the new device")
		}
	case err := <-joinErr:
		t.Fatalf("JoinWithInvite: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("new device did not see the approval")
	}

	// The invite is single use.
	doc, _ := n.Document()
	if inv, ok := doc.InviteByID(created.Invite.ID); !ok || inv.UsedBy != newKey.DeviceID {
		t.Fatal("invite was not marked used")
	}
	if _, err := n.ApproveInvite(e2ePass, p.Signed, "ikinci", nil, time.Now()); err == nil {
		t.Fatal("used invite approved twice")
	}
}

type sysinfoReport struct {
	os    string
	cores int
}
