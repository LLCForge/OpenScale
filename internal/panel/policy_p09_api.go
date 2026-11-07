package panel

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Rule language endpoints of P09 (ADR-0120): scope warnings and test
// results (#112, #101), the rule simulator (#102, #104), the text policy
// file (F-075, #228); new rules also take the one-time access window,
// bidirectional and ICMP type fields (#104, #281, #108).

func (s *Server) p09Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerCheck := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireNetwork(h)))
	}
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("GET /api/policy/report", owner(s.handlePolicyReport))
	mux.HandleFunc("POST /api/policy/check", ownerCheck(s.handlePolicyCheck))
	mux.HandleFunc("GET /api/policy/text", owner(s.handlePolicyText))
	mux.HandleFunc("POST /api/policy/text", ownerWrite(s.handleApplyPolicyText))
}

type policyReportResponse struct {
	Warnings []trust.PolicyWarning    `json:"warnings"`
	Tests    []trust.PolicyTestResult `json:"tests"`
}

func (s *Server) handlePolicyReport(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	resp := policyReportResponse{Warnings: doc.PolicyWarnings(s.now()), Tests: doc.RunPolicyTests()}
	if resp.Warnings == nil {
		resp.Warnings = []trust.PolicyWarning{}
	}
	writeJSON(w, http.StatusOK, resp)
}

type policyCheckRequest struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	// IgnoreTime evaluates time-limited rules as if always active.
	IgnoreTime bool `json:"ignoreTime"`
}

type policyCheckResponse struct {
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
	Rule     int    `json:"rule"`
	RuleText string `json:"ruleText"`
	// OverriddenAllow is an allow rule a deny rule overrides, or -1.
	OverriddenAllow int `json:"overriddenAllow"`
}

func (s *Server) handlePolicyCheck(w http.ResponseWriter, r *http.Request) {
	var req policyCheckRequest
	if !decodeBody(w, r, &req) {
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	for _, name := range []string{req.From, req.To} {
		if _, found := doc.DeviceByName(name); !found {
			writeError(w, http.StatusBadRequest, "Cihaz bulunamadı.")
			return
		}
	}
	q := trust.PacketQuery{ICMPType: -1}
	switch proto := trust.Protocol(strings.ToLower(strings.TrimSpace(req.Protocol))); proto {
	case trust.ProtocolTCP, trust.ProtocolUDP:
		ports, err := trust.ExpandPortNames(proto, []string{req.Port})
		n, convErr := 0, error(nil)
		if err == nil {
			n, convErr = strconv.Atoi(ports[0])
		}
		if err != nil || convErr != nil || n < 1 || n > 65535 {
			writeError(w, http.StatusBadRequest, "Port 1-65535 arasında bir sayı veya bilinen bir ad (ör. rdp) olmalı.")
			return
		}
		q.Proto, q.Port = 6, uint16(n)
		if proto == trust.ProtocolUDP {
			q.Proto = 17
		}
	case trust.ProtocolICMP:
		q.Proto, q.ICMPType = 1, 8
	default:
		n, ok := trust.ProtocolNumber(proto)
		if !ok {
			writeError(w, http.StatusBadRequest, "Protokol tcp, udp, icmp veya 0-255 arası bir numara olmalı.")
			return
		}
		q.Proto = int(n)
	}
	if !req.IgnoreTime {
		q.At = s.now()
	}
	d := doc.Explain(req.From, req.To, q)
	resp := policyCheckResponse{Allowed: d.Allowed, Reason: d.Reason, Rule: d.Rule, OverriddenAllow: -1}
	if d.Rule >= 0 && d.Rule < len(doc.Rules) {
		resp.RuleText = trust.RuleSummary(doc.Rules[d.Rule])
	}
	if d.Reason == trust.ReasonDeny && len(d.Allows) > 0 {
		resp.OverriddenAllow = d.Allows[0]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePolicyText(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	text, err := trust.FormatPolicyText(doc)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": string(text)})
}

type policyTextRequest struct {
	signRequest
	Text string `json:"text"`
	// ConfirmBroad confirms new rules that open every device to every
	// device (#112).
	ConfirmBroad bool `json:"confirmBroad"`
}

func (s *Server) handleApplyPolicyText(w http.ResponseWriter, r *http.Request) {
	var req policyTextRequest
	if !decodeBody(w, r, &req) {
		return
	}
	p, err := trust.ParsePolicyText([]byte(req.Text))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cur, ok := s.currentDocument(w)
	if !ok {
		return
	}
	if !req.DryRun && !req.ConfirmBroad {
		next, err := cur.Next(s.now(), trust.DefaultValidity)
		if err == nil {
			err = next.ApplyPolicy(p)
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		if len(trust.NewBroadRules(cur, next)) > 0 {
			writeError(w, http.StatusBadRequest, "Dosya bütün cihazlardan bütün cihazlara erişim açan yeni bir kural ekliyor; imzalamak için geniş kuralı açıkça onayla.")
			return
		}
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.ApplyPolicy(p) })
}

// applyRuleExt sets the bidirectional, ICMP type and one-time window
// fields of a new rule (#281, #108, #104), expands port names (#110) and
// refuses an unconfirmed broad rule (#112). It writes the error response
// itself and reports whether to go on.
func (s *Server) applyRuleExt(w http.ResponseWriter, rule *trust.Rule, req addRuleRequest) bool {
	if len(req.ICMPTypes) > maxRuleEntries || req.WindowMinutes < 0 || req.WindowMinutes > maxWindowMinutes {
		writeError(w, http.StatusBadRequest, "Kural geçersiz; süreli erişim 1 dakika ile 30 gün arasında olmalı.")
		return false
	}
	rule.Bidirectional = req.Bidirectional
	if len(req.ICMPTypes) > 0 {
		rule.ICMPTypes = req.ICMPTypes
	}
	if req.WindowMinutes > 0 {
		// The owner's signature is the approval; the rule closes by itself.
		rule.NotAfter = s.now().Add(time.Duration(req.WindowMinutes) * time.Minute).UTC().Truncate(time.Second)
	}
	if rule.Service == "" {
		ports, err := trust.ExpandPortNames(rule.Protocol, rule.Ports)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return false
		}
		rule.Ports = ports
	}
	if req.DryRun || req.ConfirmBroad {
		return true
	}
	cur, ok := s.currentDocument(w)
	if !ok {
		return false
	}
	if cur.IsBroadRule(*rule) {
		writeError(w, http.StatusBadRequest, "Bu kural bütün cihazlardan bütün cihazlara erişim açar; imzalamak için açıkça onayla.")
		return false
	}
	return true
}

// maxWindowMinutes bounds a one-time access window (30 days).
const maxWindowMinutes = 30 * 24 * 60
