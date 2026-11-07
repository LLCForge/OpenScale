package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Access request from a member device (#383, ADR-0158). The user of a
// member device asks for access ("SSH to the desktop"); the request is
// signed with the device's own signing key and waits in the owner's inbox.
// Nothing is granted automatically: the owner approves it and the root key
// signs an ordinary, time-limited rule. A request never changes the
// document by itself and is not part of it.

// AccessRequestContext is the Ed25519 context of an access request.
const AccessRequestContext = "openscale/access-request/v1"

// Access request limits.
const (
	accessRequestPrefix = "osreq1."
	// MaxAccessHours bounds the lifetime of the rule an approval creates.
	MaxAccessHours = 30 * 24
	// AccessRequestMaxAge is how long a request can wait for approval.
	AccessRequestMaxAge = 7 * 24 * time.Hour
	accessRequestSkew   = 5 * time.Minute
	maxAccessReason     = 200
	maxAccessPayload    = 1024
	maxAccessLine       = 2048
	accessNonceSize     = 16
	maxAccessPorts      = 8
)

// AccessRequest is the signed payload.
type AccessRequest struct {
	NetworkID string      `json:"network_id"`
	DeviceID  string      `json:"device_id"`
	From      string      `json:"from"`
	To        string      `json:"to"`
	Service   RuleService `json:"service,omitempty"`
	Protocol  Protocol    `json:"protocol,omitempty"`
	Ports     []string    `json:"ports,omitempty"`
	Users     []string    `json:"users,omitempty"`
	Hours     int         `json:"hours"`
	Reason    string      `json:"reason,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	Nonce     []byte      `json:"nonce"`
}

type signedAccessRequest struct {
	Payload   []byte `json:"p"`
	Signature []byte `json:"s"`
}

// AccessRequestInput is what the requesting user chooses.
type AccessRequestInput struct {
	To       string
	Service  RuleService
	Protocol Protocol
	Ports    []string
	Users    []string
	Hours    int
	Reason   string
}

func (r *AccessRequest) check() error {
	switch {
	case !isValidID(r.NetworkID) || !isValidID(r.DeviceID):
		return errors.New("access request has an invalid id")
	case r.From == "" || r.To == "" || r.From == r.To || len(r.From) > 64 || len(r.To) > 64:
		return errors.New("access request has an invalid source or target")
	case r.Hours < 1 || r.Hours > MaxAccessHours:
		return fmt.Errorf("access request must last 1-%d hours", MaxAccessHours)
	case len(r.Reason) > maxAccessReason || !utf8.ValidString(r.Reason) || strings.IndexFunc(r.Reason, unicode.IsControl) >= 0:
		return errors.New("access request reason is invalid")
	case len(r.Nonce) != accessNonceSize:
		return errors.New("access request has no nonce")
	case len(r.Ports) > maxAccessPorts:
		return errors.New("access request lists too many ports")
	case len(r.Users) > maxAccessPorts:
		return errors.New("access request lists too many accounts")
	}
	if r.Service != ServiceSSH && len(r.Users) > 0 {
		return errors.New("only an ssh request names accounts")
	}
	if r.Service != "" {
		if r.Protocol != "" || len(r.Ports) > 0 {
			return errors.New("a service request has no protocol or ports of its own")
		}
		return nil
	}
	if r.Protocol != ProtocolTCP && r.Protocol != ProtocolUDP {
		return errors.New("access request needs a service or tcp/udp with ports")
	}
	if len(r.Ports) == 0 {
		return errors.New("access request needs at least one port")
	}
	return nil
}

// Rule is the time-limited rule an approval signs. hours may shorten the
// requested duration (0 keeps it); it can never lengthen it.
func (r *AccessRequest) Rule(now time.Time, hours int) (Rule, error) {
	if hours == 0 {
		hours = r.Hours
	}
	if hours < 1 || hours > r.Hours {
		return Rule{}, fmt.Errorf("approved duration must be 1-%d hours", r.Hours)
	}
	desc := "Erişim isteği"
	if r.Reason != "" {
		desc += ": " + r.Reason
	}
	if len(desc) > maxDescriptionLen {
		desc = truncateUTF8(desc, maxDescriptionLen)
	}
	rule := Rule{
		From:        []string{r.From},
		To:          []string{r.To},
		Service:     r.Service,
		Protocol:    r.Protocol,
		Ports:       append([]string{}, r.Ports...),
		Users:       append([]string(nil), r.Users...),
		Description: desc,
		NotAfter:    now.UTC().Truncate(time.Second).Add(time.Duration(hours) * time.Hour),
	}
	if rule.Service != "" {
		rule.Ports = []string{}
	}
	return rule, nil
}

func truncateUTF8(s string, n int) string {
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// NewAccessRequest signs a request for this device, which must be a member
// of doc.
func (s *DeviceSecrets) NewAccessRequest(doc *Document, in AccessRequestInput, now time.Time, random io.Reader) (string, *AccessRequest, error) {
	signing, _, err := s.PublicKeys()
	if err != nil {
		return "", nil, err
	}
	var self *Device
	for i := range doc.Devices {
		if doc.Devices[i].ID == s.DeviceID && doc.Devices[i].SigningKey == signing {
			self = &doc.Devices[i]
		}
	}
	if self == nil {
		return "", nil, errors.New("this device is not a member of the network")
	}
	if _, ok := doc.DeviceByName(in.To); !ok {
		return "", nil, ErrUnknownDevice
	}
	nonce := make([]byte, accessNonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", nil, fmt.Errorf("generate nonce: %w", err)
	}
	r := &AccessRequest{
		NetworkID: doc.NetworkID, DeviceID: self.ID, From: self.Name, To: in.To,
		Service: in.Service, Protocol: in.Protocol, Ports: in.Ports, Users: in.Users, Hours: in.Hours,
		Reason: strings.TrimSpace(in.Reason), CreatedAt: roundTimestamp(now), Nonce: nonce,
	}
	if err := r.check(); err != nil {
		return "", nil, err
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return "", nil, err
	}
	sig, err := s.SigningKey().Sign(nil, payload, &ed25519.Options{Context: AccessRequestContext})
	if err != nil {
		return "", nil, err
	}
	data, err := json.Marshal(signedAccessRequest{Payload: payload, Signature: sig})
	if err != nil {
		return "", nil, err
	}
	return accessRequestPrefix + base64.RawURLEncoding.EncodeToString(data), r, nil
}

// OpenAccessRequest verifies a request line against doc: the signer must be
// a current, unexpired member whose name matches the request, the target
// must exist and the request must not be older than AccessRequestMaxAge.
// It returns the request and a stable id (the payload digest).
func OpenAccessRequest(doc *Document, line string, now time.Time) (*AccessRequest, string, error) {
	line = strings.Join(strings.Fields(line), "")
	if len(line) > maxAccessLine || !strings.HasPrefix(line, accessRequestPrefix) {
		return nil, "", errors.New("not an OpenScale access request")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, accessRequestPrefix))
	if err != nil {
		return nil, "", errors.New("access request is damaged")
	}
	var sr signedAccessRequest
	if err := decodeStrict(data, &sr); err != nil || len(sr.Payload) > maxAccessPayload {
		return nil, "", errors.New("access request is damaged")
	}
	var r AccessRequest
	if err := decodeStrict(sr.Payload, &r); err != nil {
		return nil, "", errors.New("access request is damaged")
	}
	if err := r.check(); err != nil {
		return nil, "", err
	}
	if r.NetworkID != doc.NetworkID {
		return nil, "", errors.New("access request is for another network")
	}
	var signer *Device
	for i := range doc.Devices {
		if doc.Devices[i].ID == r.DeviceID {
			signer = &doc.Devices[i]
		}
	}
	if signer == nil || signer.Name != r.From {
		return nil, "", errors.New("access request comes from a device that is not a member")
	}
	if !now.Before(signer.ExpiresAt) {
		return nil, "", errors.New("the requesting device's membership has expired")
	}
	if len(sr.Signature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(signer.SigningKey[:], sr.Payload, sr.Signature, &ed25519.Options{Context: AccessRequestContext}) != nil {
		return nil, "", ErrBadSignature
	}
	if r.CreatedAt.After(now.Add(accessRequestSkew)) || now.Sub(r.CreatedAt) > AccessRequestMaxAge {
		return nil, "", errors.New("access request is too old or dated in the future")
	}
	if _, ok := doc.DeviceByName(r.To); !ok {
		return nil, "", ErrUnknownDevice
	}
	sum := sha256.Sum256(sr.Payload)
	return &r, hex.EncodeToString(sum[:12]), nil
}
