package trust

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Limits on tags and groups (ADR-0021).
const (
	MaxGroups        = 64
	MaxTags          = 16
	maxGroupMembers  = 256
	maxExitUsers     = maxRuleEntries
	errUnknownGroupF = "%s references unknown group %q"
)

// ErrGroupNotFound is returned when a named group does not exist.
var ErrGroupNotFound = errors.New("group not found")

// Group names a set of devices and tags. Rules, other groups' members and
// exit_users refer to it as "group:<name>". Members are device names or
// "tag:<name>" references; groups do not nest.
type Group struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// GroupByName returns the group with the given name.
func (doc *Document) GroupByName(name string) (Group, bool) {
	for _, g := range doc.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// SetGroup creates the named group or replaces its members. An empty member
// list is allowed; such a group matches no device.
func (doc *Document) SetGroup(name string, members []string) error {
	g := Group{Name: name, Members: append([]string{}, members...)}
	return doc.transact(func() error {
		if idx := slices.IndexFunc(doc.Groups, func(x Group) bool { return x.Name == name }); idx >= 0 {
			doc.Groups[idx] = g
		} else {
			doc.Groups = append(doc.Groups, g)
		}
		return nil
	})
}

// RemoveGroup deletes the named group. It fails while a rule or exit_users
// still refers to the group, so no reference silently stops matching.
func (doc *Document) RemoveGroup(name string) error {
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.Groups, func(x Group) bool { return x.Name == name })
		if idx < 0 {
			return ErrGroupNotFound
		}
		doc.Groups = slices.Delete(doc.Groups, idx, idx+1)
		if len(doc.Groups) == 0 {
			doc.Groups = nil
		}
		return nil
	})
}

// SetDeviceTags replaces the tags of the named device.
func (doc *Document) SetDeviceTags(name string, tags []string) error {
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
		if idx < 0 {
			return ErrUnknownDevice
		}
		doc.Devices[idx].Tags = cleanTags(tags)
		return nil
	})
}

// SetExitUsers restricts exit node use to the listed devices, tags and
// groups. An empty list means no device may use an exit node.
func (doc *Document) SetExitUsers(users []string) error {
	list := append([]string{}, users...)
	return doc.transact(func() error {
		doc.ExitUsers = &list
		return nil
	})
}

// ClearExitUsers removes the restriction: every device may use exit nodes
// again, as before ADR-0021.
func (doc *Document) ClearExitUsers() error {
	return doc.transact(func() error {
		doc.ExitUsers = nil
		return nil
	})
}

// ExitUsersList returns the exit_users list and whether the restriction is
// set at all.
func (doc *Document) ExitUsersList() ([]string, bool) {
	if doc.ExitUsers == nil {
		return nil, false
	}
	return append([]string{}, (*doc.ExitUsers)...), true
}

// SetRuleDisabled turns the rule at index (0-based) off or back on.
func (doc *Document) SetRuleDisabled(index int, disabled bool) error {
	if index < 0 || index >= len(doc.Rules) {
		return errors.New("rule not found")
	}
	doc.Rules[index].Disabled = disabled
	return doc.Validate()
}

// TagUsage reports tag references in rules, groups and exit_users that no
// device or pending invite carries. Such a reference matches nothing; for
// a deny rule that usually means a typo, so the panel shows it as a
// warning. It is not an error because a tag may be planned for devices
// that join later.
func (doc *Document) TagUsage() []string {
	have := map[string]bool{}
	for _, d := range doc.Devices {
		for _, t := range d.Tags {
			have[t] = true
		}
	}
	for _, inv := range doc.Invites {
		for _, t := range inv.Tags {
			have[t] = true
		}
	}
	seen := map[string]bool{}
	var unused []string
	check := func(entries []string) {
		for _, e := range entries {
			if t, ok := strings.CutPrefix(e, TagPrefix); ok && !have[t] && !seen[t] {
				seen[t] = true
				unused = append(unused, t)
			}
		}
	}
	for _, r := range doc.Rules {
		check(r.From)
		check(r.To)
		check(r.Via)
	}
	for _, g := range doc.Groups {
		check(g.Members)
	}
	if doc.ExitUsers != nil {
		check(*doc.ExitUsers)
	}
	slices.Sort(unused)
	return unused
}

func (doc *Document) validateGroups(names map[string]bool) (map[string]bool, error) {
	if len(doc.Groups) > MaxGroups {
		return nil, fmt.Errorf("at most %d groups are allowed", MaxGroups)
	}
	groups := make(map[string]bool, len(doc.Groups))
	for i, g := range doc.Groups {
		if !isValidLabel(g.Name) {
			return nil, fmt.Errorf("group %d: name must be a lowercase DNS label", i)
		}
		if groups[g.Name] {
			return nil, fmt.Errorf("group %d (%s): duplicate name", i, g.Name)
		}
		if len(g.Members) > maxGroupMembers {
			return nil, fmt.Errorf("group %s: at most %d members are allowed", g.Name, maxGroupMembers)
		}
		seen := make(map[string]bool, len(g.Members))
		for _, m := range g.Members {
			if strings.HasPrefix(m, GroupPrefix) || m == RuleWildcard {
				return nil, fmt.Errorf("group %s: members must be devices, tags or address ranges", g.Name)
			}
			// CIDR and "host:" members (#277) are checked against the
			// network prefixes and routes by validateF4A.
			if !isAddrEntry(m) {
				if err := validateReference("group "+g.Name, m, names, nil); err != nil {
					return nil, err
				}
			}
			if seen[m] {
				return nil, fmt.Errorf("group %s lists %q twice", g.Name, m)
			}
			seen[m] = true
		}
		groups[g.Name] = true
	}
	return groups, nil
}

func (doc *Document) validateExitUsers(names, groups map[string]bool) error {
	if doc.ExitUsers == nil {
		return nil
	}
	users := *doc.ExitUsers
	if len(users) > maxExitUsers {
		return fmt.Errorf("exit_users allows at most %d entries", maxExitUsers)
	}
	seen := make(map[string]bool, len(users))
	for _, u := range users {
		if u == RuleWildcard {
			return errors.New("exit_users must not contain *; remove the list to allow every device")
		}
		if !isAddrEntry(u) { // ranges (#277): validateF4A
			if err := validateReference("exit_users", u, names, groups); err != nil {
				return err
			}
		}
		if seen[u] {
			return fmt.Errorf("exit_users lists %q twice", u)
		}
		seen[u] = true
	}
	return nil
}

// validateReference checks a device name, "tag:x" or "group:x" entry. A
// nil groups map means group references are not allowed here.
func validateReference(field, e string, names, groups map[string]bool) error {
	if t, ok := strings.CutPrefix(e, TagPrefix); ok {
		if !isValidLabel(t) {
			return fmt.Errorf("%s has an invalid tag %q", field, e)
		}
		return nil
	}
	if g, ok := strings.CutPrefix(e, GroupPrefix); ok {
		if groups == nil || !groups[g] {
			return fmt.Errorf(errUnknownGroupF, field, g)
		}
		return nil
	}
	if !names[e] {
		return fmt.Errorf("%s references unknown device %q", field, e)
	}
	return nil
}

func validateTags(tags []string) error {
	if len(tags) > MaxTags {
		return fmt.Errorf("at most %d tags are allowed", MaxTags)
	}
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		if !isValidLabel(t) {
			return fmt.Errorf("tag %q must be a lowercase DNS label", t)
		}
		if seen[t] {
			return fmt.Errorf("tag %q is listed twice", t)
		}
		seen[t] = true
	}
	return nil
}

// cleanTags copies tags, accepting an optional "tag:" prefix, and returns
// nil for an empty list so the field is omitted from the document.
func cleanTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, strings.TrimPrefix(t, TagPrefix))
	}
	return out
}
