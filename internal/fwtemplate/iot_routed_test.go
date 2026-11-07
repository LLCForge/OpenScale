package fwtemplate

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

// #243: IoT isolation over ranges, also behind a subnet router.

var camLAN = netip.MustParsePrefix("192.168.50.0/24")

func cameraDoc(t *testing.T) *trust.Document {
	t.Helper()
	doc := homeDoc(t)
	if err := doc.SetDeviceRoutes("nas", []netip.Prefix{camLAN}); err != nil {
		t.Fatal(err)
	}
	// An old broad camera rule only the cameras use, and one that also
	// covers other addresses.
	for _, r := range []trust.Rule{
		{From: []string{"192.168.50.16/28"}, To: []string{"laptop"}, Protocol: trust.ProtocolTCP, Ports: []string{"80"}},
		{From: []string{"192.168.50.0/24"}, To: []string{"misafir"}, Protocol: trust.ProtocolTCP, Ports: []string{"80"}},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	return doc
}

func TestIoTIsolationRoutedCameras(t *testing.T) {
	doc := cameraDoc(t)
	p := Params{Subject: "192.168.50.16/28", Targets: []string{"ha"}, Ports: []string{"8123"}, Isolate: true}
	plan, err := Build(doc, IoTIsolation, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Added) != 2 || len(plan.Disabled) != 1 || plan.Disabled[0] != 4 {
		t.Fatalf("added %d, disabled %v", len(plan.Added), plan.Disabled)
	}
	joined := strings.Join(plan.Warnings, "\n")
	if !strings.Contains(joined, "Kural 6") || !strings.Contains(joined, "VLAN") {
		t.Fatalf("warnings: %v", plan.Warnings)
	}
	if !hasReach(plan, "192.168.50.16/28", "ha", "tcp/8123", false, true) || !hasReach(plan, "192.168.50.16/28", "laptop", "tcp/80", true, false) {
		t.Fatalf("reach: %+v", plan.Reach)
	}
	if err := plan.Apply(doc); err != nil {
		t.Fatal(err)
	}
	cam := trust.AddrEnd(netip.MustParseAddr("192.168.50.20"))
	tcp := func(port uint16) trust.PacketQuery { return trust.PacketQuery{Proto: 6, Port: port, ICMPType: -1} }
	switch {
	case !doc.AllowsRoutedPacketAt(cam, trust.DeviceEnd("ha"), tcp(8123)):
		t.Fatal("cameras reach the controller")
	case doc.AllowsRoutedPacketAt(cam, trust.DeviceEnd("ha"), tcp(22)):
		t.Fatal("only the chosen ports")
	case doc.AllowsRoutedPacketAt(cam, trust.DeviceEnd("laptop"), tcp(80)):
		t.Fatal("the narrow camera rule must be disabled")
	case !doc.AllowsRoutedPacketAt(trust.DeviceEnd("ha"), cam, tcp(554)):
		t.Fatal("the controller reaches the cameras every way")
	case doc.AllowsRoutedPacketAt(cam, trust.AddrEnd(netip.MustParseAddr("192.168.50.21")), tcp(80)):
		t.Fatal("routed hosts never reach each other through OpenScale")
	}
	if _, err := Build(doc, IoTIsolation, Params{Subject: "10.9.0.0/24", Targets: []string{"ha"}, Ports: []string{"1"}}); !errors.Is(err, ErrRange) {
		t.Fatalf("a range outside the routes: %v", err)
	}
}

func TestIoTIsolationOverlayRangeIsolate(t *testing.T) {
	doc := homeDoc(t)
	// tv and lamba get a named range that holds both.
	tv, _ := doc.DeviceByName("tv")
	lamba, _ := doc.DeviceByName("lamba")
	if err := doc.SetHost("akilli", netip.PrefixFrom(tv.IPv4, 32)); err != nil {
		t.Fatal(err)
	}
	plan, err := Build(doc, IoTIsolation, Params{Subject: "tag:iot", Targets: []string{"ha"}, Ports: []string{"8123"}, Isolate: true})
	if err != nil {
		t.Fatal(err)
	}
	deny := false
	for _, r := range plan.Added {
		deny = deny || (r.IsDeny() && r.From[0] == "tag:iot" && r.To[0] == "tag:iot")
	}
	if !deny || !plan.ExitUsersChanged || len(plan.ExitUsers) != 4 {
		t.Fatalf("isolation: deny %v, exit %v %v", deny, plan.ExitUsersChanged, plan.ExitUsers)
	}
	if err := plan.Apply(doc); err != nil {
		t.Fatal(err)
	}
	if doc.Allows("tv", "lamba", trust.ProtocolTCP, 8123) || doc.MayUseExitNode("tv") || !doc.MayUseExitNode("laptop") {
		t.Fatal("isolated devices must not reach each other or the internet")
	}
	// A single-address range selects its device.
	plan, err = Build(doc, IoTIsolation, Params{Subject: "host:akilli", Targets: []string{"nas"}, Ports: []string{"445"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Allows("nas", "tv", trust.ProtocolTCP, 1) || doc.Allows("nas", lamba.Name, trust.ProtocolTCP, 1) {
		t.Fatal("the range rule covers only its device")
	}
	if _, err := Build(doc, Guest, Params{Subject: "misafir", Targets: []string{"nas"}, Ports: []string{"445"}, Isolate: true}); err == nil {
		t.Fatal("isolate is an iot-isolation option")
	}
}
