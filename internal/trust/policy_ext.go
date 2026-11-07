package trust

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Rule language extensions of ADR-0120 (P09): addresses and named
// addresses in rules (F-073, #277), bidirectional rules (F-079, #281),
// ICMP type filtering (#108), time windows and schedules (#103, #104) and
// policy tests kept in the document (F-076, #101).
//
// Every new field is optional and omitted when unset, so a document that
// does not use them encodes byte for byte as before and every existing rule
// keeps its meaning.

// HostPrefix starts a reference to a named address in a rule entry
// ("host:nas"). Device names cannot contain ':' and CIDR entries always
// contain '/', so neither can be mistaken for a device.
const HostPrefix = "host:"

// Limits of the ADR-0120 fields.
const (
	MaxHosts        = 64
	MaxPolicyTests  = 256
	maxICMPTypes    = 16
	maxScheduleDays = 7
)

// ErrPolicyTestFailed is wrapped when a policy test does not hold. Signing
// refuses such a document (ADR-0120).
var ErrPolicyTestFailed = errors.New("kural testi başarısız")

// NamedAddress gives an address range a name usable in rules as
// "host:<name>". The range must lie inside the network's own prefixes:
// ranges outside the overlay only make sense with subnet routing, which
// this document format does not describe yet (ADR-0120).
type NamedAddress struct {
	Name   string       `json:"name"`
	Prefix netip.Prefix `json:"prefix"`
}

// RuleSchedule limits a rule to some hours of some week days. Times are
// "HH:MM" in the fixed UTC offset (no daylight saving rules); End may be
// earlier than Start for a window that crosses midnight, in which case the
// window belongs to the day it starts on.
type RuleSchedule struct {
	// Days are mon, tue, wed, thu, fri, sat, sun; empty means every day.
	Days  []string `json:"days,omitempty"`
	Start string   `json:"start"`
	End   string   `json:"end"`
	// UTCOffset is "+03:00" or "-05:30"; empty means UTC.
	UTCOffset string `json:"utc_offset,omitempty"`
}

// PolicyTest is an expectation kept in the document (F-076). Signing runs
// every test and refuses the document when one fails.
type PolicyTest struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Protocol is tcp, udp, icmp (an echo request) or an IANA number;
	// empty for a service test.
	Protocol Protocol `json:"protocol,omitempty"`
	Port     uint16   `json:"port,omitempty"`
	// Service tests an application service (ssh needs User).
	Service RuleService `json:"service,omitempty"`
	User    string      `json:"user,omitempty"`
	// Expect is "allow" or "deny".
	Expect RuleAction `json:"expect"`
	// At evaluates time-limited rules at this instant. Without it time
	// conditions are ignored, so a test gives the same answer whenever the
	// document is signed.
	At          time.Time `json:"at,omitzero"`
	Description string    `json:"description,omitempty"`
}

// PacketQuery describes one new connection for rule evaluation.
type PacketQuery struct {
	// Proto is the IANA protocol number (6 tcp, 17 udp, 1 and 58 icmp).
	Proto int
	// Port is the destination port for tcp and udp.
	Port uint16
	// ICMPType is the ICMP or ICMPv6 type, or -1 when unknown.
	ICMPType int
	// At is the evaluation time; the zero time ignores time conditions.
	At time.Time
}

// Decision explains a rule evaluation (#102, #104 simulator).
type Decision struct {
	Allowed bool `json:"allowed"`
	// Rule is the index of the deciding rule: the first matching deny rule,
	// otherwise the first matching allow rule; -1 for default deny.
	Rule int `json:"rule"`
	// Reason is self, deny, allow or default_deny.
	Reason string `json:"reason"`
	// Allows lists every matching allow rule (also when a deny rule wins).
	Allows []int `json:"allows"`
}

// Decision reasons.
const (
	ReasonSelf        = "self"
	ReasonDeny        = "deny"
	ReasonAllow       = "allow"
	ReasonDefaultDeny = "default_deny"
)

// timeNow is the clock of runtime decisions (Allows, AllowsIP and the
// service checks). Time-limited rules depend on the device clock.
var timeNow = time.Now

// ICMP type numbers the rule language knows by name.
const (
	icmpV4Echo = 8
	icmpV6Echo = 128
)

// HasTimeConditions reports whether the rule applies only at some times.
func (r Rule) HasTimeConditions() bool {
	return !r.NotBefore.IsZero() || !r.NotAfter.IsZero() || r.Schedule != nil
}

// ActiveAt reports whether the rule's time conditions hold at t. The zero
// time ignores them.
func (r Rule) ActiveAt(t time.Time) bool {
	if t.IsZero() || !r.HasTimeConditions() {
		return true
	}
	if !r.NotBefore.IsZero() && t.Before(r.NotBefore) {
		return false
	}
	if !r.NotAfter.IsZero() && !t.Before(r.NotAfter) {
		return false
	}
	if r.Schedule != nil {
		return r.Schedule.Contains(t)
	}
	return true
}

var weekDays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// Contains reports whether t falls inside the schedule. An invalid
// schedule contains nothing.
func (s *RuleSchedule) Contains(t time.Time) bool {
	start, ok1 := parseClock(s.Start, false)
	end, ok2 := parseClock(s.End, true)
	off, ok3 := parseUTCOffset(s.UTCOffset)
	if !ok1 || !ok2 || !ok3 || start == end {
		return false
	}
	local := t.UTC().Add(off)
	minute := local.Hour()*60 + local.Minute()
	day := local.Weekday()
	if start < end {
		return s.hasDay(day) && minute >= start && minute < end
	}
	// The window crosses midnight.
	if minute >= start {
		return s.hasDay(day)
	}
	return minute < end && s.hasDay((day+6)%7)
}

func (s *RuleSchedule) hasDay(d time.Weekday) bool {
	return len(s.Days) == 0 || slices.Contains(s.Days, weekDays[d])
}

// parseClock parses "HH:MM" into minutes after midnight. "24:00" is
// accepted only as an end time.
func parseClock(s string, isEnd bool) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if isEnd && h == 24 && m == 0 {
		return 24 * 60, true
	}
	if h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// parseUTCOffset parses "", "+03:00" or "-05:30" (between -12:00 and
// +14:00).
func parseUTCOffset(s string) (time.Duration, bool) {
	if s == "" {
		return 0, true
	}
	if len(s) != 6 || (s[0] != '+' && s[0] != '-') {
		return 0, false
	}
	mins, ok := parseClock(s[1:], false)
	if !ok {
		return 0, false
	}
	if s[0] == '-' {
		mins = -mins
	}
	if mins < -12*60 || mins > 14*60 || (mins == 0 && s[0] == '-') {
		return 0, false
	}
	return time.Duration(mins) * time.Minute, true
}

// FormatUTCOffset renders a zone offset in seconds as "+03:00".
func FormatUTCOffset(seconds int) string {
	sign := '+'
	if seconds < 0 {
		sign, seconds = '-', -seconds
	}
	return fmt.Sprintf("%c%02d:%02d", sign, seconds/3600, seconds%3600/60)
}

// isAddrEntry reports whether a rule entry is a CIDR range or a named
// address rather than a device, tag or group.
func isAddrEntry(e string) bool {
	return strings.HasPrefix(e, HostPrefix) || strings.Contains(e, "/")
}

// entryPrefix resolves a CIDR or "host:" entry.
func (doc *Document) entryPrefix(e string) (netip.Prefix, bool) {
	if h, ok := strings.CutPrefix(e, HostPrefix); ok {
		for _, n := range doc.Hosts {
			if n.Name == h {
				return n.Prefix, true
			}
		}
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(e)
	return p, err == nil
}

// addrEntryMatches reports whether one of the device's tunnel addresses lies
// in the entry's range. Rules decide per device, so a range that contains
// a device's IPv4 address covers its IPv6 traffic too.
func (doc *Document) addrEntryMatches(e string, s subject) bool {
	p, ok := doc.entryPrefix(e)
	if !ok {
		return false
	}
	return (s.v4.IsValid() && p.Contains(s.v4)) || (s.v6.IsValid() && p.Contains(s.v6))
}

// ruleCovers reports whether the rule's endpoints cover traffic from src to
// dst, in either direction for a bidirectional rule.
func (doc *Document) ruleCovers(r Rule, src, dst subject) bool {
	to := r.trafficTo()
	if doc.matchesAny(r.From, src) && doc.matchesAny(to, dst) {
		return true
	}
	return r.Bidirectional && doc.matchesAny(r.From, dst) && doc.matchesAny(to, src)
}

// ruleMatchesPacket checks protocol, port and ICMP type.
func ruleMatchesPacket(r Rule, q PacketQuery) bool {
	if !protoMatches(r, q.Proto, q.Port) {
		return false
	}
	if len(r.ICMPTypes) == 0 {
		return true
	}
	if q.ICMPType < 0 {
		// Unknown type: a type-limited allow rule does not open it, a
		// type-limited deny rule still refuses it (fail closed).
		return r.IsDeny()
	}
	v6 := q.Proto == ipProtoICMPv6
	for _, e := range r.ICMPTypes {
		if e == "echo" {
			if (!v6 && q.ICMPType == icmpV4Echo) || (v6 && q.ICMPType == icmpV6Echo) {
				return true
			}
			continue
		}
		fam, n, ok := parseICMPType(e)
		if ok && fam == v6 && int(n) == q.ICMPType {
			return true
		}
	}
	return false
}

// parseICMPType parses "v4:<n>" or "v6:<n>".
func parseICMPType(e string) (v6 bool, n uint8, ok bool) {
	var num string
	switch {
	case strings.HasPrefix(e, "v4:"):
		num = e[3:]
	case strings.HasPrefix(e, "v6:"):
		v6, num = true, e[3:]
	default:
		return false, 0, false
	}
	n, ok = ProtocolNumber(Protocol(num))
	return v6, n, ok
}

// icmpTypeAllowedInRule rejects types a rule must not name: error messages
// pass only as part of a tracked flow (F-083) and echo replies only as the
// reply of a tracked request, never because of a rule.
func icmpTypeAllowedInRule(v6 bool, n uint8) bool {
	if v6 {
		return n >= 128 && n != 129
	}
	switch n {
	case 0, 3, 4, 5, 11, 12:
		return false
	}
	return true
}

// evaluate is the single rule evaluation behind Allows, AllowsIP,
// AllowsPacketAt and Explain (ADR-0021 order, ADR-0120 fields).
func (doc *Document) evaluate(src, dst string, q PacketQuery) Decision {
	d := Decision{Rule: -1, Reason: ReasonDefaultDeny}
	if src == dst {
		d.Reason = ReasonSelf
		return d
	}
	if doc.Lockdown != nil { // #361, p01_fields.go
		return doc.lockdownDecision(src, dst)
	}
	s, t := doc.subject(src), doc.subject(dst)
	deny := -1
	for i, r := range doc.Rules {
		if r.Disabled || !r.ActiveAt(q.At) || !ruleMatchesPacket(r, q) || !doc.ruleCovers(r, s, t) {
			continue
		}
		if r.IsDeny() {
			if deny < 0 {
				deny = i
			}
			continue
		}
		d.Allows = append(d.Allows, i)
	}
	switch {
	case deny >= 0:
		d.Rule, d.Reason = deny, ReasonDeny
	case len(d.Allows) > 0:
		d.Allowed, d.Rule, d.Reason = true, d.Allows[0], ReasonAllow
	}
	return d
}

// AllowsPacketAt reports whether device src may open the connection q to
// device dst. The packet filter calls it with the ICMP type and its clock.
func (doc *Document) AllowsPacketAt(src, dst string, q PacketQuery) bool {
	return doc.evaluate(src, dst, q).Allowed
}

// Explain evaluates q from src to dst and says which rule decides (#102).
func (doc *Document) Explain(src, dst string, q PacketQuery) Decision {
	return doc.evaluate(src, dst, q)
}

// HasTimeRules reports whether any enabled rule has time conditions.
func (doc *Document) HasTimeRules() bool {
	for _, r := range doc.Rules {
		if !r.Disabled && r.HasTimeConditions() {
			return true
		}
	}
	return false
}

// TimeRuleState returns a fingerprint of which time-limited rules are
// active at t. The packet filter forgets its connection table when it
// changes, like on a new document version, so a closing window also ends
// the connections it allowed.
func (doc *Document) TimeRuleState(t time.Time) string {
	var b strings.Builder
	for i, r := range doc.Rules {
		if r.Disabled || !r.HasTimeConditions() {
			continue
		}
		if r.ActiveAt(t) {
			b.WriteString(strconv.Itoa(i))
			b.WriteByte(',')
		}
	}
	return b.String()
}

// --- validation ---

// validateTrafficEntries checks a rule's from or to list. It accepts what
// validateRuleEntries accepts plus CIDR and "host:" entries, whose
// meaning validatePolicyExt checks against the document.
func validateTrafficEntries(field string, entries []string, names, groups map[string]bool) error {
	if len(entries) == 0 || len(entries) > maxRuleEntries {
		return fmt.Errorf("%s needs 1-%d entries", field, maxRuleEntries)
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e != RuleWildcard && !isAddrEntry(e) {
			if err := validateReference(field, e, names, groups); err != nil {
				return err
			}
		}
		if seen[e] {
			return fmt.Errorf("%s lists %q twice", field, e)
		}
		seen[e] = true
	}
	return nil
}

// insideOverlay reports whether p lies inside one of the network prefixes.
func (doc *Document) insideOverlay(p netip.Prefix) bool {
	for _, o := range []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix} {
		if o.IsValid() && p.Addr().Is4() == o.Addr().Is4() && p.Bits() >= o.Bits() && o.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// validateOverlayPrefix checks a CIDR written in a rule or named address.
func (doc *Document) validateOverlayPrefix(what string, p netip.Prefix, text string) error {
	if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" || p.Addr().Is4In6() || (text != "" && p.String() != text) {
		return fmt.Errorf("%s: %q is not a masked CIDR range", what, text)
	}
	// Outside the overlay a range must lie inside one approved subnet
	// route (ADR-0133).
	if !doc.insideOverlay(p) && !doc.insideApprovedRoute(p) {
		return fmt.Errorf("%s: %s lies outside the network prefixes and every approved subnet route", what, p)
	}
	return nil
}

func (doc *Document) validateHosts() (map[string]bool, error) {
	if len(doc.Hosts) > MaxHosts {
		return nil, fmt.Errorf("at most %d named addresses are allowed", MaxHosts)
	}
	hosts := make(map[string]bool, len(doc.Hosts))
	for i, h := range doc.Hosts {
		if !isValidLabel(h.Name) {
			return nil, fmt.Errorf("host %d: name must be a lowercase DNS label", i)
		}
		if hosts[h.Name] {
			return nil, fmt.Errorf("host %s: duplicate name", h.Name)
		}
		if err := doc.validateOverlayPrefix("host "+h.Name, h.Prefix, h.Prefix.String()); err != nil {
			return nil, err
		}
		hosts[h.Name] = true
	}
	return hosts, nil
}

// validatePolicyExt checks the ADR-0120 fields of the document and its
// rules. Rule entries other than addresses are checked by validateRules.
func (doc *Document) validatePolicyExt(names map[string]bool) error {
	hosts, err := doc.validateHosts()
	if err != nil {
		return err
	}
	for i, r := range doc.Rules {
		if err := doc.validateRuleExt(r, hosts); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return doc.validatePolicyTests(names)
}

func (doc *Document) validateRuleExt(r Rule, hosts map[string]bool) error {
	for _, list := range [][]string{r.From, r.To} {
		for _, e := range list {
			if !isAddrEntry(e) {
				continue
			}
			if h, ok := strings.CutPrefix(e, HostPrefix); ok {
				if !hosts[h] {
					return fmt.Errorf("references unknown named address %q", h)
				}
				continue
			}
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return fmt.Errorf("%q is not a CIDR range", e)
			}
			if err := doc.validateOverlayPrefix("rule", p, e); err != nil {
				return err
			}
		}
	}
	if r.Bidirectional && r.Service != "" {
		return errors.New("service rules are directional and cannot be bidirectional")
	}
	if err := validateICMPTypes(r); err != nil {
		return err
	}
	return validateRuleTime(r)
}

func validateICMPTypes(r Rule) error {
	if len(r.ICMPTypes) == 0 {
		return nil
	}
	if r.Service != "" || r.Protocol != ProtocolICMP {
		return errors.New("icmp_types needs protocol icmp")
	}
	if len(r.ICMPTypes) > maxICMPTypes {
		return fmt.Errorf("icmp_types allows at most %d entries", maxICMPTypes)
	}
	seen := make(map[string]bool, len(r.ICMPTypes))
	for _, e := range r.ICMPTypes {
		if seen[e] {
			return fmt.Errorf("icmp_types lists %q twice", e)
		}
		seen[e] = true
		if e == "echo" {
			continue
		}
		v6, n, ok := parseICMPType(e)
		if !ok {
			return fmt.Errorf("invalid icmp type %q; use echo, v4:<n> or v6:<n>", e)
		}
		if !icmpTypeAllowedInRule(v6, n) {
			return fmt.Errorf("icmp type %q is an error or reply and passes only with its flow", e)
		}
	}
	return nil
}

func validRuleTime(t time.Time) bool {
	return t.IsZero() || (t.Location() == time.UTC && t.Nanosecond() == 0 && t.Year() >= 2000 && t.Year() <= 9999)
}

func validateRuleTime(r Rule) error {
	if !validRuleTime(r.NotBefore) || !validRuleTime(r.NotAfter) {
		return errors.New("not_before and not_after must be whole seconds in UTC")
	}
	if !r.NotBefore.IsZero() && !r.NotAfter.IsZero() && !r.NotAfter.After(r.NotBefore) {
		return errors.New("not_after must be after not_before")
	}
	s := r.Schedule
	if s == nil {
		return nil
	}
	if len(s.Days) > maxScheduleDays {
		return errors.New("schedule lists too many days")
	}
	seen := map[string]bool{}
	for _, d := range s.Days {
		if !slices.Contains(weekDays, d) || seen[d] {
			return fmt.Errorf("schedule day %q is invalid or listed twice", d)
		}
		seen[d] = true
	}
	start, ok1 := parseClock(s.Start, false)
	end, ok2 := parseClock(s.End, true)
	if !ok1 || !ok2 || start == end {
		return errors.New("schedule needs start and end as HH:MM, different from each other")
	}
	if _, ok := parseUTCOffset(s.UTCOffset); !ok {
		return errors.New("schedule utc_offset must look like +03:00 (between -12:00 and +14:00)")
	}
	return nil
}

func (doc *Document) validatePolicyTests(names map[string]bool) error {
	if len(doc.PolicyTests) > MaxPolicyTests {
		return fmt.Errorf("at most %d policy tests are allowed", MaxPolicyTests)
	}
	for i, t := range doc.PolicyTests {
		if err := validatePolicyTest(t, names); err != nil {
			return fmt.Errorf("policy test %d: %w", i, err)
		}
	}
	return nil
}

func validatePolicyTest(t PolicyTest, names map[string]bool) error {
	if !names[t.From] || !names[t.To] {
		return errors.New("from and to must name devices of the network")
	}
	if t.From == t.To {
		return errors.New("from and to must differ")
	}
	if t.Expect != RuleAllow && t.Expect != RuleDeny {
		return errors.New(`expect must be "allow" or "deny"`)
	}
	if !validRuleTime(t.At) {
		return errors.New("at must be whole seconds in UTC")
	}
	if err := validateDescription(t.Description); err != nil {
		return err
	}
	if t.Service != "" {
		switch {
		case t.Service.Port() == 0:
			return fmt.Errorf("unknown service %q", t.Service)
		case t.Service == ServiceWake:
			return errors.New("wake tests are not supported; test the relay with a tcp test")
		case t.Protocol != "" || t.Port != 0:
			return errors.New("service tests must not set protocol or port")
		case t.Service == ServiceSSH && t.User != SSHRootUser && !ValidSSHUser(t.User):
			return errors.New("ssh tests need a valid user")
		case t.Service != ServiceSSH && t.User != "":
			return errors.New("only ssh tests may set user")
		}
		return nil
	}
	if t.User != "" {
		return errors.New("only ssh tests may set user")
	}
	switch t.Protocol {
	case ProtocolTCP, ProtocolUDP:
		if t.Port == 0 {
			return fmt.Errorf("%s tests need a port", t.Protocol)
		}
	case ProtocolICMP:
		if t.Port != 0 {
			return errors.New("icmp tests must not set a port")
		}
	default:
		n, ok := ProtocolNumber(t.Protocol)
		if !ok || namedProtocol(n) {
			return fmt.Errorf("test protocol %q must be tcp, udp, icmp or another IANA number", t.Protocol)
		}
		if t.Port != 0 {
			return errors.New("only tcp and udp tests may set a port")
		}
	}
	return nil
}

// --- policy tests ---

// PolicyTestResult is the outcome of one policy test.
type PolicyTestResult struct {
	Index    int      `json:"index"`
	Test     string   `json:"test"`
	Passed   bool     `json:"passed"`
	Got      string   `json:"got"`
	Decision Decision `json:"decision"`
}

// String renders a test as "laptop -> masaustu tcp/3389 izin".
func (t PolicyTest) String() string {
	what := string(t.Protocol)
	switch {
	case t.Service != "":
		what = "servis " + string(t.Service)
		if t.User != "" {
			what += " (" + t.User + ")"
		}
	case t.Port != 0:
		what += "/" + strconv.Itoa(int(t.Port))
	}
	expect := "izin"
	if t.Expect == RuleDeny {
		expect = "ret"
	}
	s := t.From + " -> " + t.To + " " + what + " beklenen: " + expect
	if !t.At.IsZero() {
		s += " (" + t.At.UTC().Format(time.RFC3339) + ")"
	}
	return s
}

// query returns the packet a non-service test sends.
func (t PolicyTest) query() PacketQuery {
	q := PacketQuery{Port: t.Port, ICMPType: -1, At: t.At}
	switch t.Protocol {
	case ProtocolTCP:
		q.Proto = ipProtoTCP
	case ProtocolUDP:
		q.Proto = ipProtoUDP
	case ProtocolICMP:
		q.Proto, q.ICMPType = ipProtoICMP, icmpV4Echo
	default:
		n, _ := ProtocolNumber(t.Protocol)
		q.Proto = int(n)
	}
	return q
}

// RunPolicyTest evaluates one test against the document.
func (doc *Document) RunPolicyTest(i int, t PolicyTest) PolicyTestResult {
	var dec Decision
	if t.Service != "" {
		dec = doc.evaluate(t.From, t.To, PacketQuery{Proto: ipProtoTCP, Port: t.Service.Port(), ICMPType: -1, At: t.At})
		if dec.Allowed {
			var permits func(Rule) bool
			if t.Service == ServiceSSH {
				permits = func(r Rule) bool { return sshUserPermitted(r, t.User) }
			}
			if !doc.serviceDecisionAt(t.Service, doc.subject(t.From), doc.subject(t.To), permits, t.At) {
				dec.Allowed, dec.Reason = false, ReasonDefaultDeny
			}
		}
	} else {
		dec = doc.evaluate(t.From, t.To, t.query())
	}
	got := RuleAllow
	if !dec.Allowed {
		got = RuleDeny
	}
	return PolicyTestResult{Index: i, Test: t.String(), Passed: got == t.Expect, Got: string(got), Decision: dec}
}

// RunPolicyTests runs every test of the document.
func (doc *Document) RunPolicyTests() []PolicyTestResult {
	out := make([]PolicyTestResult, 0, len(doc.PolicyTests))
	for i, t := range doc.PolicyTests {
		out = append(out, doc.RunPolicyTest(i, t))
	}
	return out
}

// CheckPolicyTests returns an error wrapping ErrPolicyTestFailed when a test
// fails. SignDocument and the owner's Prepare call it, so a document whose
// tests fail is never signed (F-076).
func (doc *Document) CheckPolicyTests() error {
	var failed []string
	for _, res := range doc.RunPolicyTests() {
		if !res.Passed {
			got := "izin verildi"
			if res.Got == string(RuleDeny) {
				got = "reddedildi"
			}
			failed = append(failed, fmt.Sprintf("#%d %s; sonuç: %s", res.Index+1, res.Test, got))
		}
	}
	if len(failed) == 0 {
		return nil
	}
	if len(failed) > 5 {
		failed = append(failed[:5], fmt.Sprintf("ve %d test daha", len(failed)-5))
	}
	return fmt.Errorf("%w: %s", ErrPolicyTestFailed, strings.Join(failed, "; "))
}

// dropPolicyTestsFor removes the tests that name a removed device, so
// revoking a device never fails because of a test (ADR-0120).
func (doc *Document) dropPolicyTestsFor(name string) {
	if len(doc.PolicyTests) == 0 {
		return
	}
	doc.PolicyTests = slices.DeleteFunc(doc.PolicyTests, func(t PolicyTest) bool { return t.From == name || t.To == name })
	if len(doc.PolicyTests) == 0 {
		doc.PolicyTests = nil
	}
}

// renamePolicyTests follows a device rename (ADR-0019).
func (doc *Document) renamePolicyTests(oldName, newName string) {
	for i := range doc.PolicyTests {
		if doc.PolicyTests[i].From == oldName {
			doc.PolicyTests[i].From = newName
		}
		if doc.PolicyTests[i].To == oldName {
			doc.PolicyTests[i].To = newName
		}
	}
}

// --- named addresses ---

// SetHost creates or replaces a named address.
func (doc *Document) SetHost(name string, prefix netip.Prefix) error {
	h := NamedAddress{Name: name, Prefix: prefix}
	return doc.transact(func() error {
		if idx := slices.IndexFunc(doc.Hosts, func(x NamedAddress) bool { return x.Name == name }); idx >= 0 {
			doc.Hosts[idx] = h
		} else {
			doc.Hosts = append(doc.Hosts, h)
		}
		return nil
	})
}

// RemoveHost deletes a named address. It fails while a rule refers to it.
func (doc *Document) RemoveHost(name string) error {
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.Hosts, func(x NamedAddress) bool { return x.Name == name })
		if idx < 0 {
			return errors.New("named address not found")
		}
		doc.Hosts = slices.Delete(doc.Hosts, idx, idx+1)
		if len(doc.Hosts) == 0 {
			doc.Hosts = nil
		}
		return nil
	})
}
