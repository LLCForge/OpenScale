package cli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/namesuggest"
	"github.com/openscale/openscale/internal/trust"
)

// "Did you mean" hints for unknown device, group and tag names (#798).
// Every candidate comes from the document already on this computer; nothing
// is asked from the coordinator. In a members-only public part (blind
// coordinator, ADR-0178) device names are pseudonyms derived from the id,
// so those are never offered.

// knownDeviceNames lists the device names of doc that a person could have
// meant.
func knownDeviceNames(doc *trust.Document) []string {
	if doc == nil {
		return nil
	}
	sealed := trust.IsMembersOnly(doc)
	names := make([]string, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		if sealed && d.Name == trust.PublicDeviceName(d.ID) {
			continue
		}
		names = append(names, d.Name)
	}
	return names
}

// knownGroupNames lists the group names of doc.
func knownGroupNames(doc *trust.Document) []string {
	if doc == nil {
		return nil
	}
	names := make([]string, 0, len(doc.Groups))
	for _, g := range doc.Groups {
		names = append(names, g.Name)
	}
	return names
}

// knownTagNames lists the tags carried by devices and pending invites.
func knownTagNames(doc *trust.Document) []string {
	if doc == nil {
		return nil
	}
	var tags []string
	for _, d := range doc.Devices {
		tags = append(tags, d.Tags...)
	}
	for _, inv := range doc.Invites {
		tags = append(tags, inv.Tags...)
	}
	slices.Sort(tags)
	return slices.Compact(tags)
}

// suggestRef returns err with the suggestions for the first reference of
// refs that doc does not know: a device name, "group:<name>" or
// "tag:<name>"; "*" and other prefixes are skipped. err is returned
// unchanged when every reference is known or nothing is close.
func suggestRef(doc *trust.Document, err error, refs ...string) error {
	if err == nil || doc == nil {
		return err
	}
	devices := knownDeviceNames(doc)
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		switch {
		case ref == "" || ref == trust.RuleWildcard:
			continue
		case strings.HasPrefix(ref, trust.GroupPrefix):
			g := strings.TrimPrefix(ref, trust.GroupPrefix)
			if _, ok := doc.GroupByName(g); !ok {
				if w := namesuggest.Wrap(err, namesuggest.KindGroup, g, knownGroupNames(doc)); w != err {
					return w
				}
			}
		case strings.HasPrefix(ref, trust.TagPrefix):
			t := strings.TrimPrefix(ref, trust.TagPrefix)
			tags := knownTagNames(doc)
			if !slices.Contains(tags, t) {
				if w := namesuggest.Wrap(err, namesuggest.KindTag, t, tags); w != err {
					return w
				}
			}
		case strings.Contains(ref, ":"):
			continue
		default:
			if _, ok := doc.DeviceByName(ref); !ok {
				if w := namesuggest.Wrap(err, namesuggest.KindDevice, ref, devices); w != err {
					return w
				}
			}
		}
	}
	return err
}

// suggestingChange runs change and, when it fails, adds suggestions for
// the first unknown reference of refs. The candidates are read before the
// change runs, so a half-applied change cannot hide them.
func suggestingChange(change admin.Change, refs ...string) admin.Change {
	return func(doc *trust.Document) error {
		before := &trust.Document{Devices: slices.Clone(doc.Devices), Groups: slices.Clone(doc.Groups), Invites: slices.Clone(doc.Invites), MembersOnly: doc.MembersOnly}
		return suggestRef(before, change(doc), refs...)
	}
}

// deviceNotFound is the error for a device name doc does not list, with
// suggestions when one is close.
func deviceNotFound(doc *trust.Document, name string) error {
	return namesuggest.Wrap(fmt.Errorf("ağda %q adlı bir cihaz yok", name), namesuggest.KindDevice, name, knownDeviceNames(doc))
}

// withSuggestionText appends the hint of a NotFoundError to its message,
// for usage errors that are printed without errorHint.
func withSuggestionText(err error) string {
	var nf *namesuggest.NotFoundError
	if errors.As(err, &nf) {
		if h := nf.Hint(); h != "" {
			return err.Error() + ". " + h
		}
	}
	return err.Error()
}

// suggestionHint is errorHint's part for unknown names (p16.go).
func suggestionHint(err error) string {
	var nf *namesuggest.NotFoundError
	if errors.As(err, &nf) {
		return nf.Hint()
	}
	return ""
}

// printTagSuggestion adds the closest known tags to an unused tag warning.
func printTagSuggestion(w io.Writer, doc *trust.Document, tag string) {
	if h := namesuggest.FormatHint(namesuggest.Suggest(tag, knownTagNames(doc), namesuggest.MaxSuggestions), trust.TagPrefix); h != "" {
		fmt.Fprintf(w, "  %s\n", h)
	}
}
