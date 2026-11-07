package privacy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/osnet"
)

// Linux system cleanup of "openscale uninstall --purge" (#52). Run as
// root, it stops and disables OpenScale's own systemd units and deletes
// OpenScale's own nftables tables (the kill switch, DNS, exit node, split
// tunnel and the other "openscale" / "openscale_*" tables). Nothing else is
// ever touched: the unit and table names are read from the system, and
// each one must match OpenScale's naming before a command is built for it.
// A dry run only reads.

var (
	// ErrNotRoot is returned when the cleanup needs root and does not have it.
	ErrNotRoot = errors.New("root yetkisi gerekli: Linux servisleri ve nft tabloları kaldırılamadı")
	// ErrNotOwned is returned for a unit or table that is not OpenScale's.
	ErrNotOwned = errors.New("openscale birimi veya tablosu değil")
)

// openScaleUnit matches openscale.service, openscale-device.service,
// openscale-wait-online.service, openscale@x.service and the like.
var openScaleUnit = regexp.MustCompile(`^openscale([-@][a-z0-9][a-z0-9@._-]{0,62})?\.(service|socket|timer|path)$`)

// openScaleTable matches "openscale" and "openscale_<name>".
var openScaleTable = regexp.MustCompile(`^openscale(_[a-z0-9_]{1,48})?$`)

// nftFamilies are the nftables families a table can have.
var nftFamilies = []string{"inet", "ip", "ip6", "arp", "bridge", "netdev"}

const maxCleanupItems = 64

// NFTTable is one nftables table.
type NFTTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

func (t NFTTable) String() string { return t.Family + " " + t.Name }

// IsOpenScaleUnit reports whether a systemd unit name is OpenScale's.
func IsOpenScaleUnit(name string) bool { return openScaleUnit.MatchString(name) }

// IsOpenScaleTable reports whether an nftables table is OpenScale's.
func IsOpenScaleTable(t NFTTable) bool {
	return slices.Contains(nftFamilies, t.Family) && openScaleTable.MatchString(t.Name)
}

// LinuxCleanup is what the cleanup stops and removes.
type LinuxCleanup struct {
	Units  []string   `json:"units"`
	Tables []NFTTable `json:"tables"`
	// Errors are the reads that failed (for example nft without root).
	Errors []string `json:"errors,omitempty"`
}

// ParseUnitList reads "systemctl list-unit-files"/"list-units --plain
// --no-legend" output and returns the OpenScale units, without duplicates.
func ParseUnitList(out string) []string {
	var units []string
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "●"))
		if len(f) == 0 || !IsOpenScaleUnit(f[0]) || slices.Contains(units, f[0]) {
			continue
		}
		units = append(units, f[0])
		if len(units) == maxCleanupItems {
			break
		}
	}
	return units
}

// ParseNFTTables reads "nft list tables" output and returns OpenScale's
// tables only.
func ParseNFTTables(out string) []NFTTable {
	var tables []NFTTable
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "table" {
			continue
		}
		t := NFTTable{Family: f[1], Name: f[2]}
		if !IsOpenScaleTable(t) || slices.Contains(tables, t) {
			continue
		}
		tables = append(tables, t)
		if len(tables) == maxCleanupItems {
			break
		}
	}
	return tables
}

func readUnits(ctx context.Context, out osnet.OutputRunner) ([]string, []string) {
	var units, errs []string
	for _, args := range [][]string{
		{"list-unit-files", "--no-legend", "--plain", "openscale*"},
		{"list-units", "--all", "--no-legend", "--plain", "openscale*"},
	} {
		data, err := out(ctx, osnet.Command{Tool: "systemctl", Args: args})
		if osnet.IsToolNotFound(err) {
			return nil, nil // no systemd, no OpenScale unit
		}
		if err != nil && len(data) == 0 {
			errs = append(errs, err.Error())
			continue
		}
		for _, u := range ParseUnitList(string(data)) {
			if !slices.Contains(units, u) {
				units = append(units, u)
			}
		}
	}
	return units, errs
}

func readTables(ctx context.Context, out osnet.OutputRunner) ([]NFTTable, []string) {
	data, err := out(ctx, osnet.Command{Tool: "nft", Args: []string{"list", "tables"}})
	if osnet.IsToolNotFound(err) {
		return nil, nil // without nftables there is no table to remove
	}
	if err != nil {
		return nil, []string{err.Error()}
	}
	return ParseNFTTables(string(data)), nil
}

// DiscoverLinuxCleanup reads what the cleanup would stop and remove; it
// changes nothing.
func DiscoverLinuxCleanup(ctx context.Context, out osnet.OutputRunner) LinuxCleanup {
	var c LinuxCleanup
	var errs []string
	c.Units, errs = readUnits(ctx, out)
	c.Errors = append(c.Errors, errs...)
	c.Tables, errs = readTables(ctx, out)
	c.Errors = append(c.Errors, errs...)
	return c
}

// UnitCommands returns the commands that stop and disable units.
func UnitCommands(units []string) ([]osnet.Command, error) {
	var cmds []osnet.Command
	for _, u := range units {
		if !IsOpenScaleUnit(u) {
			return nil, fmt.Errorf("%s: %w", u, ErrNotOwned)
		}
		cmds = append(cmds, osnet.Command{Tool: "systemctl", Args: []string{"disable", "--now", u}})
	}
	return cmds, nil
}

// TableCommands returns the commands that delete tables.
func TableCommands(tables []NFTTable) ([]osnet.Command, error) {
	var cmds []osnet.Command
	for _, t := range tables {
		if !IsOpenScaleTable(t) {
			return nil, fmt.Errorf("%s: %w", t, ErrNotOwned)
		}
		cmds = append(cmds, osnet.Command{Tool: "nft", Args: []string{"delete", "table", t.Family, t.Name}})
	}
	return cmds, nil
}

// Plan returns every command the cleanup runs, for a dry run.
func (c LinuxCleanup) Plan() ([]osnet.Command, error) {
	units, err := UnitCommands(c.Units)
	if err != nil {
		return nil, err
	}
	tables, err := TableCommands(c.Tables)
	if err != nil {
		return nil, err
	}
	return append(units, tables...), nil
}

// LinuxCleanupOptions configure RunLinuxCleanup; zero values use the system.
type LinuxCleanupOptions struct {
	DryRun bool
	Output osnet.OutputRunner
	Run    osnet.Runner
	// IsRoot reports whether the process runs as root; nil uses the
	// effective user ID.
	IsRoot func() bool
}

// RunLinuxCleanup stops and disables OpenScale's units, then deletes the
// OpenScale tables still present (a stopped service removes some of its own
// tables). With DryRun it only reads and returns what would be done. It
// keeps going after a failed command and returns every error joined.
func RunLinuxCleanup(ctx context.Context, o LinuxCleanupOptions) (LinuxCleanup, error) {
	if o.Output == nil {
		if runtime.GOOS != "linux" {
			return LinuxCleanup{}, nil
		}
		o.Output = osnet.SystemOutput
	}
	c := DiscoverLinuxCleanup(ctx, o.Output)
	if o.DryRun {
		return c, nil
	}
	isRoot := o.IsRoot
	if isRoot == nil {
		isRoot = func() bool { return os.Geteuid() == 0 }
	}
	if !isRoot() {
		return c, ErrNotRoot
	}
	var errs []error
	units, err := UnitCommands(c.Units)
	if err != nil {
		return c, err
	}
	if err := osnet.RunAll(ctx, units, o.Run); err != nil {
		errs = append(errs, err)
	}
	if len(c.Units) > 0 {
		if err := osnet.RunAll(ctx, []osnet.Command{{Tool: "systemctl", Args: []string{"daemon-reload"}}}, o.Run); err != nil {
			errs = append(errs, err)
		}
	}
	// Read the tables again: stopping the services may have removed some.
	tables, readErrs := readTables(ctx, o.Output)
	if len(readErrs) > 0 {
		errs = append(errs, errors.New(strings.Join(readErrs, "; ")))
	}
	c.Tables = tables
	cmds, err := TableCommands(tables)
	if err != nil {
		return c, errors.Join(append(errs, err)...)
	}
	if err := osnet.RunAll(ctx, cmds, o.Run); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}
