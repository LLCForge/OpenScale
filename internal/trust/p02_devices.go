package trust

import (
	"errors"
	"slices"
	"time"
)

// Device flows of package P02: "like this device" (#357) and the lost
// device report (#367). Neither changes the document format.

// LikeSuggestion is what "add like <source>" proposes for target. The owner
// edits it in the diff screen before signing.
type LikeSuggestion struct {
	Source string `json:"source"`
	Target string `json:"target"`
	// Tags are the source's tags the target does not carry yet.
	Tags []string `json:"tags"`
	// Groups name the groups that list the source by name.
	Groups []string `json:"groups"`
	// Rules are copies of the rules that name the source directly, with
	// the source replaced by the target. Rules that match through tags
	// or groups need no copy: the tags and groups above cover them.
	Rules []Rule `json:"rules"`
	// ExitUser is true when an exit_users list names the source.
	ExitUser bool `json:"exitUser"`
}

func cloneRule(r Rule) Rule {
	r.From, r.To, r.Ports = slices.Clone(r.From), slices.Clone(r.To), slices.Clone(r.Ports)
	r.Users, r.Via, r.Folders, r.ICMPTypes = slices.Clone(r.Users), slices.Clone(r.Via), slices.Clone(r.Folders), slices.Clone(r.ICMPTypes)
	return r
}

func replaceName(list []string, from, to string) ([]string, bool) {
	if !slices.Contains(list, from) {
		return list, false
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if e == from {
			e = to
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out, true
}

// LikeDevice proposes the tags, groups, rules and exit permission of source
// for target. Rules that would make the target talk to itself are skipped.
func (doc *Document) LikeDevice(source, target string) (LikeSuggestion, error) {
	src, ok := doc.DeviceByName(source)
	if !ok {
		return LikeSuggestion{}, ErrUnknownDevice
	}
	dst, ok := doc.DeviceByName(target)
	if !ok {
		return LikeSuggestion{}, ErrUnknownDevice
	}
	if source == target {
		return LikeSuggestion{}, errors.New("a device cannot be copied onto itself")
	}
	s := LikeSuggestion{Source: source, Target: target, Tags: []string{}, Groups: []string{}, Rules: []Rule{}}
	for _, t := range src.Tags {
		if !slices.Contains(dst.Tags, t) {
			s.Tags = append(s.Tags, t)
		}
	}
	for _, g := range doc.Groups {
		if slices.Contains(g.Members, source) && !slices.Contains(g.Members, target) {
			s.Groups = append(s.Groups, g.Name)
		}
	}
	for _, r := range doc.Rules {
		c := cloneRule(r)
		var inFrom, inTo, inVia bool
		c.From, inFrom = replaceName(c.From, source, target)
		c.To, inTo = replaceName(c.To, source, target)
		c.Via, inVia = replaceName(c.Via, source, target)
		if !inFrom && !inTo && !inVia {
			continue
		}
		// A rule from the target to only itself is meaningless.
		if len(c.From) == 1 && len(c.To) == 1 && c.From[0] == target && c.To[0] == target {
			continue
		}
		if !slices.ContainsFunc(doc.Rules, func(x Rule) bool { return sameRule(x, c) }) {
			s.Rules = append(s.Rules, c)
		}
	}
	if users, ok := doc.ExitUsersList(); ok && slices.Contains(users, source) && !slices.Contains(users, target) {
		s.ExitUser = true
	}
	return s, nil
}

func sameRule(a, b Rule) bool {
	return slices.Equal(a.From, b.From) && slices.Equal(a.To, b.To) && slices.Equal(a.Via, b.Via) &&
		a.Protocol == b.Protocol && slices.Equal(a.Ports, b.Ports) && a.Service == b.Service && a.Action == b.Action
}

// ApplyLike applies the parts of s the owner kept. Tags are added to the
// target's own tags; rules are appended; the target joins the groups and,
// when exitUser is set, the exit_users list.
func (doc *Document) ApplyLike(s LikeSuggestion, exitUser bool) error {
	dst, ok := doc.DeviceByName(s.Target)
	if !ok {
		return ErrUnknownDevice
	}
	if len(s.Tags) > 0 {
		tags := slices.Clone(dst.Tags)
		for _, t := range s.Tags {
			if !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
		if err := doc.SetDeviceTags(s.Target, tags); err != nil {
			return err
		}
	}
	for _, name := range s.Groups {
		i := slices.IndexFunc(doc.Groups, func(g Group) bool { return g.Name == name })
		if i < 0 {
			return errors.New("group not found")
		}
		if !slices.Contains(doc.Groups[i].Members, s.Target) {
			members := append(slices.Clone(doc.Groups[i].Members), s.Target)
			if err := doc.SetGroup(name, members); err != nil {
				return err
			}
		}
	}
	for _, r := range s.Rules {
		if err := doc.AddRule(cloneRule(r)); err != nil {
			return err
		}
	}
	if exitUser {
		if users, ok := doc.ExitUsersList(); ok && !slices.Contains(users, s.Target) {
			if err := doc.SetExitUsers(append(slices.Clone(users), s.Target)); err != nil {
				return err
			}
		}
	}
	return doc.Validate()
}

// ExposureRule is one enabled allow rule that involves a device.
type ExposureRule struct {
	Index       int         `json:"index"`
	Description string      `json:"description"`
	From        []string    `json:"from"`
	To          []string    `json:"to"`
	Service     RuleService `json:"service,omitempty"`
	Protocol    Protocol    `json:"protocol,omitempty"`
	Ports       []string    `json:"ports"`
	// OnlyThisDevice is true when the device is the rule's only source
	// (outbound) or only destination (inbound) by name: removing the
	// device leaves the rule empty.
	OnlyThisDevice bool `json:"onlyThisDevice"`
}

// DeviceExposure is what a device can reach and what reaches it.
type DeviceExposure struct {
	Name      string         `json:"name"`
	Roles     []Role         `json:"roles"`
	Tags      []string       `json:"tags"`
	Groups    []string       `json:"groups"`
	Routes    []string       `json:"routes"`
	ExitUser  bool           `json:"exitUser"`
	ExpiresAt time.Time      `json:"expiresAt"`
	Outbound  []ExposureRule `json:"outbound"`
	Inbound   []ExposureRule `json:"inbound"`
}

// DeviceExposure lists the enabled allow rules that let name reach other
// devices or let others reach it, with its roles, groups and routes.
func (doc *Document) DeviceExposure(name string) (DeviceExposure, error) {
	d, ok := doc.DeviceByName(name)
	if !ok {
		return DeviceExposure{}, ErrUnknownDevice
	}
	e := DeviceExposure{Name: name, Roles: append([]Role{}, d.Roles...), Tags: append([]string{}, d.Tags...),
		Groups: []string{}, Routes: []string{}, ExpiresAt: d.ExpiresAt, Outbound: []ExposureRule{}, Inbound: []ExposureRule{}}
	sub := doc.subject(name)
	for g := range sub.groups {
		e.Groups = append(e.Groups, g)
	}
	slices.Sort(e.Groups)
	for _, p := range d.Routes {
		e.Routes = append(e.Routes, p.String())
	}
	if users, ok := doc.ExitUsersList(); !ok || doc.matchesAny(users, sub) {
		e.ExitUser = true
	}
	for i, r := range doc.Rules {
		if r.Disabled || r.IsDeny() {
			continue
		}
		view := ExposureRule{Index: i, Description: r.Description, From: slices.Clone(r.From), To: slices.Clone(r.To),
			Service: r.Service, Protocol: r.Protocol, Ports: append([]string{}, r.Ports...)}
		to := r.trafficTo()
		out := doc.matchesAny(r.From, sub) || (r.Bidirectional && doc.matchesAny(to, sub))
		in := doc.matchesAny(to, sub) || (r.Bidirectional && doc.matchesAny(r.From, sub))
		if out {
			v := view
			v.OnlyThisDevice = len(r.From) == 1 && r.From[0] == name
			e.Outbound = append(e.Outbound, v)
		}
		if in {
			v := view
			v.OnlyThisDevice = len(to) == 1 && to[0] == name
			e.Inbound = append(e.Inbound, v)
		}
	}
	return e, nil
}

// DropRulesOnlyFor removes the rules whose only source or only destination
// is name, and returns how many were removed. Used when a lost device's
// membership is ended without revoking it (#367).
func (doc *Document) DropRulesOnlyFor(name string) int {
	n := 0
	kept := doc.Rules[:0]
	for _, r := range doc.Rules {
		to := r.trafficTo()
		if (len(r.From) == 1 && r.From[0] == name) || (len(to) == 1 && to[0] == name) {
			n++
			continue
		}
		kept = append(kept, r)
	}
	doc.Rules = kept
	return n
}
