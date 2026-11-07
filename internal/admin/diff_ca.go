package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/openscale/openscale/internal/trust"
)

// internalCAChanges describes changes of the internal CA (ADR-0138).
func internalCAChanges(prev, next *trust.Document) []string {
	a, b := prev.InternalCA, next.InternalCA
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		return []string{fmt.Sprintf("İç CA eklendi: dağıtıcı %s, sertifika %s, sertifika ömrü %d gün", b.Issuer, caDigest(b.Certificate), lifetimeDays(b))}
	case b == nil:
		return []string{"İç CA kaldırıldı (güven depolarına eklenmiş CA sertifikasını elle silin)"}
	}
	var out []string
	if !bytes.Equal(a.Certificate, b.Certificate) {
		out = append(out, fmt.Sprintf("İç CA sertifikası değişti: %s -> %s", caDigest(a.Certificate), caDigest(b.Certificate)))
	}
	if a.Issuer != b.Issuer {
		out = append(out, fmt.Sprintf("İç CA dağıtıcısı: %s -> %s", a.Issuer, b.Issuer))
	}
	if lifetimeDays(a) != lifetimeDays(b) {
		out = append(out, fmt.Sprintf("İç CA sertifika ömrü: %d -> %d gün", lifetimeDays(a), lifetimeDays(b)))
	}
	return out
}

func lifetimeDays(ca *trust.InternalCA) int { return int(ca.Lifetime().Hours() / 24) }

// caDigest is a short SHA-256 of the certificate for the diff.
func caDigest(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(sum[:8])
}
