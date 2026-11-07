package trust

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Two-channel invite code (#359, ADR-0157). The invite code is split into
// two parts that travel over different channels (for example a message and
// a phone call). Part A is the usual code with the invite seed masked;
// part B is a short secret that unmasks it. Holding only one part gives no
// usable seed, so it cannot start an enrollment. The 4-digit short code and
// the owner's approval stay exactly as before.

const (
	splitInvitePrefixA = "osinv2a."
	splitInvitePrefixB = "osinv2b."
	// SplitSecretSize is the size of part B's secret (128 bits).
	SplitSecretSize = 16
	splitCheckSize  = 4
	splitGroup      = 5
)

var splitB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrSplitMismatch is returned when the two parts do not belong together.
var ErrSplitMismatch = errors.New("the two parts of the invite code do not belong together")

// ErrSplitPartMissing is returned when only one part was given.
var ErrSplitPartMissing = errors.New("the invite code has two parts; both are needed")

type splitInviteA struct {
	Code  InviteCode `json:"c"`
	Check []byte     `json:"k"`
}

func splitMask(secret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, "openscale/invite/split/v1", InviteSeedSize)
}

func splitCheck(seed []byte) []byte {
	h := sha256.New()
	h.Write([]byte("openscale/invite/split-check/v1"))
	h.Write(seed)
	return h.Sum(nil)[:splitCheckSize]
}

// SplitInviteCode returns the two parts of c. Part B is grouped for reading
// aloud ("osinv2b.ABCDE-FGHIJ-...").
func SplitInviteCode(c *InviteCode, random io.Reader) (partA, partB string, err error) {
	if err := c.validate(); err != nil {
		return "", "", err
	}
	secret := make([]byte, SplitSecretSize)
	if _, err := io.ReadFull(random, secret); err != nil {
		return "", "", fmt.Errorf("generate split secret: %w", err)
	}
	defer clear(secret)
	mask, err := splitMask(secret)
	if err != nil {
		return "", "", err
	}
	defer clear(mask)
	masked := *c
	masked.Seed = make([]byte, InviteSeedSize)
	subtle.XORBytes(masked.Seed, c.Seed, mask)
	data, err := json.Marshal(splitInviteA{Code: masked, Check: splitCheck(c.Seed)})
	if err != nil {
		return "", "", fmt.Errorf("encode invite part: %w", err)
	}
	partA = splitInvitePrefixA + base64.RawURLEncoding.EncodeToString(data)
	if len(partA) > maxInviteChars/2 {
		return "", "", errors.New("invite code is too long to split")
	}
	return partA, splitInvitePrefixB + groupSecret(splitB32.EncodeToString(secret)), nil
}

func groupSecret(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += splitGroup {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+splitGroup, len(s))])
	}
	return b.String()
}

// CombineInviteParts joins part A and part B (with or without its prefix,
// in any letter case, with or without dashes) into the invite code.
func CombineInviteParts(partA, partB string) (*InviteCode, error) {
	a := strings.Join(strings.Fields(partA), "")
	b := strings.Join(strings.Fields(partB), "")
	if a == "" || b == "" {
		return nil, ErrSplitPartMissing
	}
	if len(a) > maxInviteChars || !strings.HasPrefix(a, splitInvitePrefixA) {
		return nil, errors.New("not the first part of an OpenScale invite code")
	}
	if len(b) > 128 {
		return nil, errors.New("the second part of the invite code is damaged")
	}
	if strings.HasPrefix(strings.ToLower(b), splitInvitePrefixB) {
		b = b[len(splitInvitePrefixB):]
	}
	b = strings.ToUpper(strings.ReplaceAll(b, "-", ""))
	secret, err := splitB32.DecodeString(b)
	if err != nil || len(secret) != SplitSecretSize {
		return nil, errors.New("the second part of the invite code is damaged")
	}
	defer clear(secret)
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(a, splitInvitePrefixA))
	if err != nil {
		return nil, errors.New("the first part of the invite code is damaged")
	}
	var p splitInviteA
	if err := decodeStrict(data, &p); err != nil || len(p.Check) != splitCheckSize || len(p.Code.Seed) != InviteSeedSize {
		return nil, errors.New("the first part of the invite code is damaged")
	}
	mask, err := splitMask(secret)
	if err != nil {
		return nil, err
	}
	defer clear(mask)
	seed := make([]byte, InviteSeedSize)
	subtle.XORBytes(seed, p.Code.Seed, mask)
	if subtle.ConstantTimeCompare(splitCheck(seed), p.Check) != 1 {
		clear(seed)
		return nil, ErrSplitMismatch
	}
	c := p.Code
	c.Seed = seed
	return &c, c.validate()
}

// IsSplitInvite reports whether text holds a part of a two-channel invite.
func IsSplitInvite(text string) bool {
	l := strings.ToLower(text)
	return strings.Contains(l, splitInvitePrefixA) || strings.Contains(l, splitInvitePrefixB)
}

// decodeSplitInvite accepts both parts in one string in either order (for
// example pasted into the same field). Neither part contains a '.', so the
// prefixes are unambiguous separators.
func decodeSplitInvite(line string) (*InviteCode, error) {
	lower := strings.ToLower(line)
	ia, ib := strings.Index(lower, splitInvitePrefixA), strings.Index(lower, splitInvitePrefixB)
	if ia < 0 || ib < 0 {
		return nil, ErrSplitPartMissing
	}
	var a, b string
	if ia < ib {
		a, b = line[ia:ib], line[ib:]
	} else {
		b, a = line[ib:ia], line[ia:]
	}
	return CombineInviteParts(a, b)
}
