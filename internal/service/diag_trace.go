package service

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// Packet trace (F-187): how the signed rules treat one new connection,
// rule by rule, in the order the packet filter evaluates them (ADR-0021).
// The explanation is built here from the document; the verdict is always
// checked against trust.Document.AllowsIP, the function the packet filter
// itself calls, so the two can never silently disagree.

// IANA protocol numbers used by the trace.
const (
	traceProtoICMP = 1
	traceProtoTCP  = 6
	traceProtoUDP  = 17
)

// traceSubject is a device as rule entries see it.
type traceSubject struct {
	name   string
	tags   []string
	groups []string
}

func subjectOf(doc *trust.Document, d trust.Device) traceSubject {
	return traceSubject{name: d.Name, tags: d.Tags, groups: groupsOf(doc, d)}
}

// entryMatch reports whether one rule entry covers s and why.
func entryMatch(e string, s traceSubject) (bool, string) {
	if e == trust.RuleWildcard {
		return true, "*"
	}
	if t, ok := strings.CutPrefix(e, trust.TagPrefix); ok {
		return slices.Contains(s.tags, t), e
	}
	if g, ok := strings.CutPrefix(e, trust.GroupPrefix); ok {
		return slices.Contains(s.groups, g), e
	}
	return e == s.name, e
}

func entriesMatch(entries []string, s traceSubject) (bool, string) {
	for _, e := range entries {
		if ok, why := entryMatch(e, s); ok {
			return true, why
		}
	}
	return false, ""
}

// parseTraceProto returns the IP protocol number and its display name.
func parseTraceProto(p string) (int, string, error) {
	switch strings.ToLower(p) {
	case "tcp":
		return traceProtoTCP, "tcp", nil
	case "udp":
		return traceProtoUDP, "udp", nil
	case "icmp", "ping":
		return traceProtoICMP, "icmp", nil
	}
	if n, ok := trust.ProtocolNumber(trust.Protocol(p)); ok {
		return int(n), strconv.Itoa(int(n)), nil
	}
	return 0, "", fmt.Errorf("protokol %q geçersiz; tcp, udp, icmp veya 0-255 arası bir numara yazın", p)
}

func traceProtoMatches(r trust.Rule, num int, port uint16) (bool, string) {
	switch r.Protocol {
	case trust.ProtocolAny:
		return true, "her protokol"
	case trust.ProtocolICMP:
		return num == traceProtoICMP || num == 58, "icmp"
	case trust.ProtocolTCP, trust.ProtocolUDP:
		want := traceProtoTCP
		if r.Protocol == trust.ProtocolUDP {
			want = traceProtoUDP
		}
		if num != want {
			return false, string(r.Protocol)
		}
		for _, spec := range r.Ports {
			lo, hi, err := trust.ParsePortRange(spec)
			if err == nil && port >= lo && port <= hi {
				return true, string(r.Protocol) + "/" + spec
			}
		}
		return false, string(r.Protocol) + " portları " + strings.Join(r.Ports, ",")
	}
	n, ok := trust.ProtocolNumber(r.Protocol)
	return ok && int(n) == num, "protokol " + string(r.Protocol)
}

// TracePacket explains how doc treats a new connection from req.Src to
// req.Dst. self and shields describe the device the trace runs on: its
// shields refuse every new connection to it whatever the rules say.
func TracePacket(doc *trust.Document, self string, shields bool, req panel.TraceRequest) (panel.TraceResult, error) {
	num, protoName, err := parseTraceProto(req.Proto)
	if err != nil {
		return panel.TraceResult{}, err
	}
	var port uint16
	if num == traceProtoTCP || num == traceProtoUDP {
		if req.Port < 1 || req.Port > 65535 {
			return panel.TraceResult{}, errors.New("tcp ve udp için hedef port (1-65535) gerekli")
		}
		port = uint16(req.Port)
	}
	res := panel.TraceResult{Schema: panel.DiagSchema, Proto: protoName, Port: int(port), Steps: []panel.TraceStep{}}
	step := func(stage, outcome, detail string) {
		res.Steps = append(res.Steps, panel.TraceStep{Stage: stage, Outcome: outcome, Detail: detail})
	}
	src, ok := FindDevice(doc, req.Src)
	if !ok {
		return res, fmt.Errorf("kaynak %q ağ belgesinde yok", req.Src)
	}
	res.Src = src.Name
	step("kaynak", "bulundu", fmt.Sprintf("%s (%s, %s)", src.Name, src.IPv4, src.IPv6))

	// A destination outside the network is internet traffic through an
	// exit node (ADR-0018, ADR-0021).
	if a, err := netip.ParseAddr(req.Dst); err == nil && !doc.IPv4Prefix.Contains(a.Unmap()) && !doc.IPv6Prefix.Contains(a.Unmap()) {
		res.Dst = a.Unmap().String()
		var exits []string
		for _, d := range doc.Devices {
			if d.HasRole(trust.RoleExitNode) && d.Name != src.Name {
				exits = append(exits, d.Name)
			}
		}
		step("hedef", "internet", res.Dst+" ağın dışında: trafik yalnızca bir çıkış düğümü üzerinden gidebilir")
		if len(exits) == 0 {
			step("çıkış düğümü", "yok", "ağda çıkış düğümü rolü verilmiş cihaz yok")
			res.Verdict = "Reddedilir: ağda çıkış düğümü yok."
			return res, nil
		}
		step("çıkış düğümü", "var", strings.Join(exits, ", "))
		if !doc.MayUseExitNode(src.Name) {
			step("exit_users", "eşleşmedi", src.Name+" çıkış düğümü kullanabilecek cihazlar listesinde değil")
			res.Verdict = "Reddedilir: kaynak çıkış düğümü kullanamaz (exit_users)."
			return res, nil
		}
		step("exit_users", "izin", src.Name+" çıkış düğümü kullanabilir")
		res.Allowed = true
		res.Verdict = "İzin verilir: kaynak bir çıkış düğümü seçtiğinde trafik oradan internete çıkar."
		return res, nil
	}
	dst, ok := FindDevice(doc, req.Dst)
	if !ok {
		return res, fmt.Errorf("hedef %q ağ belgesinde yok", req.Dst)
	}
	res.Dst = dst.Name
	step("hedef", "bulundu", fmt.Sprintf("%s (%s, %s)", dst.Name, dst.IPv4, dst.IPv6))
	if src.Name == dst.Name {
		step("aynı cihaz", "ret", "bir cihazın kendisine giden trafiği tünelden geçmez; kurallar uygulanmaz")
		res.Verdict = "Reddedilir: kaynak ve hedef aynı cihaz."
		return res, nil
	}
	if doc.Visible(src.Name, dst.Name) {
		step("eşleşme", "tünel var", "iki cihaz en az bir kuralla birbirini görüyor; WireGuard eşi olarak yapılandırılır")
	} else {
		step("eşleşme", "tünel yok", "hiçbir etkin izin kuralı iki cihazı birleştirmiyor; birbirlerini eş olarak görmezler")
	}

	s, d := subjectOf(doc, src), subjectOf(doc, dst)
	allowedBy, deniedBy := 0, 0
	for i, r := range doc.Rules {
		stage := fmt.Sprintf("kural %d", i+1)
		text := admin.RuleString(r)
		if r.Disabled {
			step(stage, "atlandı", "devre dışı: "+text)
			continue
		}
		fromOK, fromWhy := entriesMatch(r.From, s)
		if !fromOK {
			step(stage, "eşleşmedi", "kaynak kuralın 'kimden' listesinde değil: "+text)
			continue
		}
		toOK, toWhy := entriesMatch(r.To, d)
		if !toOK {
			step(stage, "eşleşmedi", "hedef kuralın 'kime' listesinde değil: "+text)
			continue
		}
		protoOK, protoWhy := traceProtoMatches(r, num, port)
		if !protoOK {
			step(stage, "eşleşmedi", "protokol veya port uymuyor ("+protoWhy+"): "+text)
			continue
		}
		why := fmt.Sprintf("kimden %s, kime %s, %s", fromWhy, toWhy, protoWhy)
		if r.IsDeny() {
			step(stage, "REDDET", why+": "+text+" (reddet kuralı her zaman kazanır)")
			deniedBy = i + 1
			break
		}
		step(stage, "İZİN", why+": "+text)
		if allowedBy == 0 {
			allowedBy = i + 1
		}
	}
	if len(doc.Rules) == 0 {
		step("kurallar", "yok", "belgede hiç kural yok")
	}
	allowed := deniedBy == 0 && allowedBy > 0
	switch {
	case deniedBy > 0:
		res.Verdict = fmt.Sprintf("Reddedilir: kural %d reddediyor.", deniedBy)
	case allowedBy > 0:
		res.Verdict = fmt.Sprintf("İzin verilir: kural %d izin veriyor.", allowedBy)
	default:
		res.Verdict = "Reddedilir: hiçbir kural izin vermiyor (varsayılan ret)."
	}
	// The filter's own answer is the truth.
	// AllowsPacketAt also applies CIDR, bidirectional, ICMP type (an echo
	// request for ping) and time conditions (ADR-0120).
	q := trust.PacketQuery{Proto: num, Port: port, ICMPType: -1, At: time.Now()}
	if num == traceProtoICMP {
		q.ICMPType = 8
	}
	if real := doc.AllowsPacketAt(src.Name, dst.Name, q); real != allowed {
		step("denetim", "uyuşmazlık", "açıklama paket süzgecinin kararıyla uyuşmadı; süzgecin kararı geçerli")
		allowed = real
		if real {
			res.Verdict = "İzin verilir (paket süzgecinin kararı)."
		} else {
			res.Verdict = "Reddedilir (paket süzgecinin kararı)."
		}
	}
	if allowed && shields && dst.Name == self {
		step("kalkanlar", "ret", "bu cihazda kalkanlar açık: diğer cihazların açtığı yeni bağlantılar reddedilir")
		allowed = false
		res.Verdict = "Reddedilir: hedef cihazda kalkanlar açık."
	}
	if num == traceProtoICMP && allowed {
		step("icmp", "not", "yanıt (echo reply) yalnızca izlenen bir isteğe aitse geçer")
	}
	res.Allowed = allowed
	return res, nil
}
