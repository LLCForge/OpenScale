package osnet

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
)

// Host name announcements over mDNS (#40, ADR-0189). avahi-daemon and
// systemd-resolved announce the computer name ("ayse-laptop.local") on
// every local network. While the owner asks for the host name to be hidden
// (opsec.json "dhcp_random_name"), the tunnel run turns both off and turns
// them back on when it stops:
//
//   - avahi: the running avahi-daemon units are stopped for this run with
//     systemctl stop (never disabled, no configuration file is changed) and
//     started again afterwards;
//   - systemd-resolved: only the per-link runtime setting is changed with
//     "resolvectl mdns <link> no" and restored to the previous value; the
//     persistent resolved.conf is never touched.
//
// MDNSState is what was on before, so the restore puts back exactly that
// and nothing the owner had off. It is journaled before the change.

// avahiUnits are the avahi units that may announce the name.
var avahiUnits = []string{"avahi-daemon.socket", "avahi-daemon.service"}

// maxMDNSLinks bounds the links read from resolvectl.
const maxMDNSLinks = 32

// MDNSLink is one resolved link whose mDNS setting was on.
type MDNSLink struct {
	Interface string `json:"interface"`
	// Previous is the link's setting before the change: "yes" or
	// "resolve".
	Previous string `json:"previous"`
}

// MDNSState is what announced the host name before the change.
type MDNSState struct {
	// AvahiUnits are the avahi units that were active.
	AvahiUnits []string   `json:"avahi_units,omitempty"`
	Links      []MDNSLink `json:"links,omitempty"`
}

// Empty reports whether nothing announced the name.
func (s MDNSState) Empty() bool { return len(s.AvahiUnits) == 0 && len(s.Links) == 0 }

// OutputRunner runs one command and returns its standard output.
type OutputRunner func(ctx context.Context, c Command) ([]byte, error)

// SystemOutput runs a system tool by absolute path (F-125) with the fixed
// environment and returns its standard output.
func SystemOutput(ctx context.Context, c Command) ([]byte, error) {
	cmd, err := toolCommand(ctx, c.Tool, c.Args...)
	if err != nil {
		return nil, err
	}
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", c.Tool, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ErrMDNSState wraps a state that cannot be restored safely.
var ErrMDNSState = errors.New("mDNS durumu geçersiz")

func validMDNSValue(v string) bool { return v == "yes" || v == "resolve" || v == "no" }

// validMDNSLink accepts a link name that is safe as a resolvectl argument.
func validMDNSLink(s string) bool { return s != "lo" && !strings.HasPrefix(s, "-") && validIface(s) }

// ParseResolvectlMDNS reads "resolvectl mdns" output ("Global: no",
// "Link 3 (wlan0): yes") and returns the links whose setting is on.
// Loopback, unknown values and unsafe names are skipped.
func ParseResolvectlMDNS(out string) []MDNSLink {
	var links []MDNSLink
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Link ") {
			continue
		}
		open, closing := strings.IndexByte(line, '('), strings.Index(line, "):")
		if open < 0 || closing < open {
			continue
		}
		iface := line[open+1 : closing]
		value := strings.ToLower(strings.TrimSpace(line[closing+2:]))
		if !validMDNSLink(iface) || !validMDNSValue(value) || value == "no" {
			continue
		}
		links = append(links, MDNSLink{Interface: iface, Previous: value})
		if len(links) == maxMDNSLinks {
			break
		}
	}
	return links
}

// ReadMDNSState reads what announces the host name now; only Linux has
// these services (a nil out reads nothing elsewhere). A tool that is
// missing or fails means that part is off.
func ReadMDNSState(ctx context.Context, out OutputRunner) MDNSState {
	var s MDNSState
	if out == nil {
		if runtime.GOOS != "linux" {
			return s
		}
		out = SystemOutput
	}
	for _, u := range avahiUnits {
		data, err := out(ctx, Command{Tool: "systemctl", Args: []string{"is-active", u}})
		if err == nil && strings.TrimSpace(string(data)) == "active" {
			s.AvahiUnits = append(s.AvahiUnits, u)
		}
	}
	if data, err := out(ctx, Command{Tool: "resolvectl", Args: []string{"mdns"}}); err == nil {
		s.Links = ParseResolvectlMDNS(string(data))
	}
	return s
}

// validate refuses a state (for example from a damaged journal) that would
// run anything other than the fixed avahi units and safe link names.
func (s MDNSState) validate() error {
	if len(s.Links) > maxMDNSLinks || len(s.AvahiUnits) > len(avahiUnits) {
		return fmt.Errorf("%w: çok fazla kayıt", ErrMDNSState)
	}
	for _, u := range s.AvahiUnits {
		if !slices.Contains(avahiUnits, u) {
			return fmt.Errorf("%w: birim %q", ErrMDNSState, u)
		}
	}
	for _, l := range s.Links {
		if !validMDNSLink(l.Interface) || !validMDNSValue(l.Previous) || l.Previous == "no" {
			return fmt.Errorf("%w: bağlantı %q=%q", ErrMDNSState, l.Interface, l.Previous)
		}
	}
	return nil
}

// MDNSHidePlan returns the commands that stop the announcements recorded in
// s and the commands that restore them. The service units are stopped in
// reverse order (service, then socket) so socket activation cannot start
// the daemon again in between.
func MDNSHidePlan(s MDNSState) (apply, restore []Command, err error) {
	if err := s.validate(); err != nil {
		return nil, nil, err
	}
	for _, l := range s.Links {
		apply = append(apply, Command{Tool: "resolvectl", Args: []string{"mdns", l.Interface, "no"}})
		restore = append(restore, Command{Tool: "resolvectl", Args: []string{"mdns", l.Interface, l.Previous}})
	}
	for i := len(s.AvahiUnits) - 1; i >= 0; i-- {
		apply = append(apply, Command{Tool: "systemctl", Args: []string{"stop", s.AvahiUnits[i]}})
	}
	for _, u := range s.AvahiUnits {
		restore = append(restore, Command{Tool: "systemctl", Args: []string{"start", u}})
	}
	return apply, restore, nil
}

// RunAll runs every command and joins the errors; unlike RunPlan it does not
// stop at the first failure (a restore should put back as much as it can).
func RunAll(ctx context.Context, cmds []Command, r Runner) error {
	if r == nil {
		r = systemRunner
	}
	var errs []error
	for _, c := range cmds {
		if err := r(ctx, c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RestoreMDNS puts back the announcements recorded in s.
func RestoreMDNS(ctx context.Context, s MDNSState) error {
	_, restore, err := MDNSHidePlan(s)
	if err != nil {
		return err
	}
	return RunAll(ctx, restore, nil)
}
