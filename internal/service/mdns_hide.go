package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
)

// Host name announcements during a tunnel run (#40, ADR-0189). The owner's
// opsec setting that hides the computer name ("dhcp_random_name" in
// opsec.json, "openscale opsec") also stops it from being announced over
// mDNS by avahi and systemd-resolved while the tunnel runs. The change is
// journaled before it is made; the run's stop puts it back, and a crash is
// undone at the next start through Journal.Recover.

// MDNSRunners are the system calls of HideMDNS; zero values use the system.
type MDNSRunners struct {
	Output osnet.OutputRunner
	Run    osnet.Runner
}

// MDNSHideWanted reports whether the opsec settings ask for the host name
// to be hidden.
func MDNSHideWanted(s node.OpsecSettings) bool { return s.DHCPRandomName }

// HideMDNS turns the announcements off for this run when want is set and
// returns the function that turns them back on (always non-nil; it does
// nothing when nothing was changed). The record stays in j until the
// restore succeeds.
func HideMDNS(ctx context.Context, j *Journal, want bool, rn MDNSRunners, logger *slog.Logger) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if !want {
		return noop, nil
	}
	state := osnet.ReadMDNSState(ctx, rn.Output)
	if state.Empty() {
		return noop, nil
	}
	apply, restore, err := osnet.MDNSHidePlan(state)
	if err != nil {
		return noop, err
	}
	if err := j.Begin(JournalEntry{Kind: JournalMDNS, MDNS: &state}); err != nil {
		return noop, fmt.Errorf("change journal: %w", err)
	}
	undo := func(ctx context.Context) error {
		if err := osnet.RunAll(ctx, restore, rn.Run); err != nil {
			return fmt.Errorf("mDNS duyurusu geri açılamadı: %w", err)
		}
		return j.Done(JournalMDNS)
	}
	if err := osnet.RunAll(ctx, apply, rn.Run); err != nil {
		// Part of it may have changed: put back what was on.
		return noop, errors.Join(fmt.Errorf("mDNS duyurusu kapatılamadı: %w", err), undo(ctx))
	}
	if logger != nil {
		logger.Info("host name announcements off for this run", "avahi_units", len(state.AvahiUnits), "resolved_links", len(state.Links))
	}
	return undo, nil
}
