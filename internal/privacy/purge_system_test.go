package privacy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/osnet"
)

const unitFilesOut = `openscale-coordinator.service disabled enabled
openscale-device.service      enabled  enabled
openscale-wait-online.service enabled  enabled
openscalex.service            enabled  enabled
sshd.service                  enabled  enabled
`

const unitsOut = `openscale-device.service loaded active running OpenScale device
● openscale-helper@1.service loaded failed failed helper
`

const tablesOut = `table inet filter
table ip nat
table inet openscale_killswitch
table inet openscale_dns
table ip6 openscale
table inet openscalebad
table inet fw
table inet openscale_dns
`

// fakeLinux plays systemctl and nft; nothing real runs.
type fakeLinux struct {
	tables string
	ran    []string
	fail   string
}

func (f *fakeLinux) output(_ context.Context, c osnet.Command) ([]byte, error) {
	switch {
	case c.Tool == "systemctl" && c.Args[0] == "list-unit-files":
		return []byte(unitFilesOut), nil
	case c.Tool == "systemctl" && c.Args[0] == "list-units":
		return []byte(unitsOut), nil
	case c.Tool == "nft" && slices.Equal(c.Args, []string{"list", "tables"}):
		return []byte(f.tables), nil
	}
	return nil, errors.New("unexpected " + c.String())
}

func (f *fakeLinux) run(_ context.Context, c osnet.Command) error {
	f.ran = append(f.ran, c.String())
	if c.Tool == "systemctl" && slices.Contains(c.Args, "openscale-device.service") {
		// The device service removes its DNS table when it stops.
		f.tables = strings.ReplaceAll(f.tables, "table inet openscale_dns\n", "")
	}
	if f.fail != "" && strings.Contains(c.String(), f.fail) {
		return errors.New("failed")
	}
	return nil
}

func TestOwnershipFilters(t *testing.T) {
	for _, u := range []string{"openscale.service", "openscale-device.service", "openscale-wait-online.service", "openscale-helper@1.service", "openscale-x.timer"} {
		if !IsOpenScaleUnit(u) {
			t.Errorf("%s refused", u)
		}
	}
	for _, u := range []string{"sshd.service", "openscalex.service", "openscale-device.mount", "openscale-.service", "../openscale.service", "openscale-device.service;reboot", "-openscale.service"} {
		if IsOpenScaleUnit(u) {
			t.Errorf("%s accepted", u)
		}
	}
	for _, tb := range []NFTTable{{"inet", "openscale"}, {"inet", "openscale_killswitch"}, {"ip6", "openscale_dns"}} {
		if !IsOpenScaleTable(tb) {
			t.Errorf("%v refused", tb)
		}
	}
	for _, tb := range []NFTTable{{"inet", "filter"}, {"ip", "nat"}, {"inet", "openscalebad"}, {"inet", "openscale_"}, {"bogus", "openscale"}, {"inet", "openscale_x;flush"}, {"inet", "OpenScale"}} {
		if IsOpenScaleTable(tb) {
			t.Errorf("%v accepted", tb)
		}
	}
}

func TestParseCleanupLists(t *testing.T) {
	units := ParseUnitList(unitFilesOut + unitsOut)
	if !slices.Equal(units, []string{"openscale-coordinator.service", "openscale-device.service", "openscale-wait-online.service", "openscale-helper@1.service"}) {
		t.Fatalf("units %v", units)
	}
	tables := ParseNFTTables(tablesOut)
	if !slices.Equal(tables, []NFTTable{{"inet", "openscale_killswitch"}, {"inet", "openscale_dns"}, {"ip6", "openscale"}}) {
		t.Fatalf("tables %v", tables)
	}
	if _, err := TableCommands([]NFTTable{{"inet", "filter"}}); !errors.Is(err, ErrNotOwned) {
		t.Fatal("foreign table planned")
	}
	if _, err := UnitCommands([]string{"sshd.service"}); !errors.Is(err, ErrNotOwned) {
		t.Fatal("foreign unit planned")
	}
}

func TestLinuxCleanupDryRunChangesNothing(t *testing.T) {
	f := &fakeLinux{tables: tablesOut}
	c, err := RunLinuxCleanup(context.Background(), LinuxCleanupOptions{DryRun: true, Output: f.output, Run: f.run, IsRoot: func() bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ran) != 0 {
		t.Fatalf("dry run ran %v", f.ran)
	}
	plan, err := c.Plan()
	if err != nil || len(plan) != 7 {
		t.Fatalf("plan %v %v", plan, err)
	}
}

func TestLinuxCleanupNeedsRoot(t *testing.T) {
	f := &fakeLinux{tables: tablesOut}
	if _, err := RunLinuxCleanup(context.Background(), LinuxCleanupOptions{Output: f.output, Run: f.run, IsRoot: func() bool { return false }}); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("err %v", err)
	}
	if len(f.ran) != 0 {
		t.Fatalf("ran without root: %v", f.ran)
	}
}

func TestLinuxCleanupRemovesOnlyOpenScale(t *testing.T) {
	f := &fakeLinux{tables: tablesOut, fail: "openscale-coordinator.service"}
	c, err := RunLinuxCleanup(context.Background(), LinuxCleanupOptions{Output: f.output, Run: f.run, IsRoot: func() bool { return true }})
	if err == nil {
		t.Fatal("failed unit not reported")
	}
	want := []string{
		"systemctl disable --now openscale-coordinator.service",
		"systemctl disable --now openscale-device.service",
		"systemctl disable --now openscale-wait-online.service",
		"systemctl disable --now openscale-helper@1.service",
		"systemctl daemon-reload",
		// openscale_dns went away with the device service.
		"nft delete table inet openscale_killswitch",
		"nft delete table ip6 openscale",
	}
	if !slices.Equal(f.ran, want) {
		t.Fatalf("ran\n%s\nwant\n%s", strings.Join(f.ran, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range f.ran {
		for _, foreign := range []string{"filter", " nat", " fw", "sshd", "openscalebad", "openscalex"} {
			if strings.Contains(r, foreign) {
				t.Fatalf("touched %q: %s", foreign, r)
			}
		}
	}
	if len(c.Tables) != 2 {
		t.Fatalf("tables %v", c.Tables)
	}
}
