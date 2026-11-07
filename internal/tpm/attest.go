package tpm

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TPM evidence at enrollment (#611, ADR-0208). A joining device can attach
// what it knows about its TPM; the owner can set a join policy that
// refuses devices without a TPM, or without an endorsement key (EK)
// certificate from an accepted manufacturer.
//
// Honest limit: without the two-round MakeCredential/ActivateCredential
// challenge (ADR-0124, not implemented), the evidence proves only that
// someone holds a copy of a TPM's EK certificate, not that the device key
// lives in that TPM. Verdicts therefore say "claim" or "ek_cert"; neither
// is "attested".

// EK certificate NV indices (TCG EK Credential Profile).
const (
	nvEKCertRSA = 0x01C00002
	nvEKCertECC = 0x01C0000A
	maxEKCert   = 4096
	nvChunk     = 768
)

// Evidence methods.
const (
	MethodNone     = "none"
	MethodPresence = "presence"
	MethodEKCert   = "ek_cert"
)

// Evidence is what a joining device states about its TPM.
type Evidence struct {
	V            int    `json:"v"`
	Method       string `json:"method"`
	TPM          bool   `json:"tpm"`
	Version      string `json:"version,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	// EKCert is the DER endorsement key certificate.
	EKCert []byte `json:"ek_cert,omitempty"`
}

// Validate checks evidence received from another device strictly.
func (e Evidence) Validate() error {
	switch {
	case e.V != 1:
		return errors.New("TPM kanıtı: sürüm")
	case e.Method != MethodNone && e.Method != MethodPresence && e.Method != MethodEKCert:
		return errors.New("TPM kanıtı: yöntem")
	case len(e.Version) > 8 || len(e.Manufacturer) > 16:
		return errors.New("TPM kanıtı: alan çok uzun")
	case len(e.EKCert) > maxEKCert:
		return errors.New("TPM kanıtı: sertifika çok büyük")
	case e.Method == MethodEKCert && len(e.EKCert) == 0:
		return errors.New("TPM kanıtı: sertifika yok")
	case !e.TPM && e.Method != MethodNone:
		return errors.New("TPM kanıtı: tutarsız")
	}
	return nil
}

// JoinPolicy is the owner's enrollment requirement. Zero asks for nothing.
type JoinPolicy struct {
	RequireTPM    bool `json:"require_tpm,omitempty"`
	RequireEKCert bool `json:"require_ek_cert,omitempty"`
	// Manufacturers, if set, lists accepted TPM vendor IDs ("INTC",
	// "AMD", "IFX", "NTC", "STM", "MSFT").
	Manufacturers []string `json:"manufacturers,omitempty"`
}

// Validate checks the policy.
func (p JoinPolicy) Validate() error {
	if len(p.Manufacturers) > 16 {
		return errors.New("çok fazla üretici")
	}
	for _, m := range p.Manufacturers {
		if m == "" || len(m) > 4 || strings.TrimSpace(m) != m {
			return fmt.Errorf("geçersiz üretici kodu %q", m)
		}
	}
	return nil
}

// Verdict is the join decision.
type Verdict struct {
	OK bool `json:"ok"`
	// Strength is "claim" (the device's statement) or "ek_cert" (an EK
	// certificate chained to an accepted root).
	Strength string   `json:"strength"`
	Reasons  []string `json:"reasons,omitempty"`
	// EKFingerprint is the SHA-256 of the EK certificate, for the owner to
	// remember which TPM joined.
	EKFingerprint string `json:"ek_fingerprint,omitempty"`
}

// EvaluateJoin applies policy to evidence. roots holds the manufacturer
// EK root certificates the owner chose to trust; nil means the chain is
// not checked and the certificate counts only as a claim.
func EvaluateJoin(p JoinPolicy, e Evidence, roots *x509.CertPool, now time.Time) Verdict {
	v := Verdict{OK: true, Strength: "claim"}
	fail := func(s string) { v.OK = false; v.Reasons = append(v.Reasons, s) }
	if err := e.Validate(); err != nil {
		fail(err.Error())
		return v
	}
	if p.RequireTPM && !e.TPM {
		fail("cihaz TPM bildirmedi; ağ politikası TPM istiyor")
	}
	if p.RequireTPM && e.TPM && e.Version != "" && e.Version != "2.0" {
		fail("TPM 2.0 değil")
	}
	if len(p.Manufacturers) > 0 {
		ok := false
		for _, m := range p.Manufacturers {
			if strings.EqualFold(m, e.Manufacturer) {
				ok = true
			}
		}
		if !ok {
			fail(fmt.Sprintf("TPM üreticisi %q kabul edilenler arasında değil", e.Manufacturer))
		}
	}
	if len(e.EKCert) > 0 {
		sum := sha256.Sum256(e.EKCert)
		v.EKFingerprint = hex.EncodeToString(sum[:])
		cert, err := x509.ParseCertificate(e.EKCert)
		switch {
		case err != nil:
			fail("EK sertifikası okunamadı")
		case roots != nil:
			// EK certificates carry a critical subject alternative name
			// with TPM attributes that crypto/x509 does not interpret.
			cert.UnhandledCriticalExtensions = nil
			_, verr := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			if verr != nil {
				fail("EK sertifikası kabul edilen üretici köklerine bağlanmıyor")
			} else {
				v.Strength = "ek_cert"
			}
		}
	}
	if p.RequireEKCert && v.Strength != "ek_cert" {
		fail("doğrulanmış EK sertifikası gerekiyor")
	}
	return v
}

// readEK allows the read-only commands needed for evidence.
var readEKCommands = map[uint32]bool{ccGetCapability: true, ccNVReadPublic: true, ccNVRead: true}

type readEKOnly struct{ t Transport }

func (r readEKOnly) Submit(cmd []byte) ([]byte, error) {
	if len(cmd) < headerSize {
		return nil, errors.New("command too short")
	}
	if cc := binary.BigEndian.Uint32(cmd[6:10]); !readEKCommands[cc] {
		return nil, fmt.Errorf("%w: 0x%08X", ErrNotAllowed, cc)
	}
	return r.t.Submit(cmd)
}

func (r readEKOnly) Close() error { return r.t.Close() }

func encodeNVReadPublic(index uint32) []byte {
	c := newCmd(tagNoSessions, ccNVReadPublic)
	c.u32(index)
	return c.bytes()
}

// encodeNVRead reads with the index's own (empty) authorization, which EK
// certificate indices allow (TPMA_NV_AUTHREAD); owner authorization is
// never used, so no hierarchy password can be tried.
func encodeNVRead(index uint32, size, offset uint16) []byte {
	c := newCmd(tagSessions, ccNVRead)
	c.u32(index) // authHandle
	c.u32(index) // nvIndex
	c.pwAuth()
	c.u16(size)
	c.u16(offset)
	return c.bytes()
}

// readNV reads a whole NV index (data size from NV_ReadPublic).
func readNV(t Transport, index uint32) ([]byte, error) {
	resp, err := t.Submit(encodeNVReadPublic(index))
	if err != nil {
		return nil, err
	}
	body, err := checkResponse(resp)
	if err != nil {
		return nil, err
	}
	r := &reader{b: body}
	pub := r.tpm2b()
	if r.err != nil {
		return nil, r.err
	}
	pr := &reader{b: pub}
	if got := pr.u32(); got != index {
		return nil, errors.New("NV index mismatch")
	}
	pr.u16()   // nameAlg
	pr.u32()   // attributes
	pr.tpm2b() // authPolicy
	size := int(pr.u16())
	if pr.err != nil || size == 0 || size > maxEKCert {
		return nil, errors.New("NV public area malformed")
	}
	out := make([]byte, 0, size)
	for len(out) < size {
		n := min(nvChunk, size-len(out))
		resp, err := t.Submit(encodeNVRead(index, uint16(n), uint16(len(out))))
		if err != nil {
			return nil, err
		}
		body, err := checkResponse(resp)
		if err != nil {
			return nil, err
		}
		rr := &reader{b: body}
		rr.u32() // parameterSize
		data := rr.tpm2b()
		if rr.err != nil || len(data) == 0 || len(data) > n {
			return nil, errors.New("NV_Read response malformed")
		}
		out = append(out, data...)
	}
	return out, nil
}

// trimDER cuts trailing padding after the outer DER SEQUENCE (EK
// certificate indices are often larger than the certificate).
func trimDER(b []byte) []byte {
	if len(b) < 4 || b[0] != 0x30 {
		return b
	}
	var n, hdr int
	switch {
	case b[1] < 0x80:
		n, hdr = int(b[1]), 2
	case b[1] == 0x81:
		n, hdr = int(b[2]), 3
	case b[1] == 0x82:
		n, hdr = int(b[2])<<8|int(b[3]), 4
	default:
		return b
	}
	if hdr+n <= len(b) {
		return b[:hdr+n]
	}
	return b
}

// CollectEvidence builds this device's evidence through t (read-only
// commands only). Without a transport it reports presence alone.
func CollectEvidence(p Presence, t Transport) Evidence {
	e := Evidence{V: 1, Method: MethodNone}
	if !p.Present {
		return e
	}
	e.TPM, e.Version, e.Method = true, p.Version, MethodPresence
	if t == nil || p.Version != "2.0" {
		return e
	}
	if info, err := Query(t); err == nil {
		e.Manufacturer = info.Manufacturer
	}
	ro := readEKOnly{t: t}
	for _, idx := range []uint32{nvEKCertRSA, nvEKCertECC} {
		if der, err := readNV(ro, idx); err == nil {
			der = trimDER(der)
			if _, err := x509.ParseCertificate(der); err == nil {
				e.EKCert, e.Method = der, MethodEKCert
				break
			}
		}
	}
	return e
}
