package admin

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Owner-side changes of package P01 (ADR-0151): several changes in one
// signature (#344, #362), the emergency lock (#361), the key age policy
// (#347) and revocation compaction (#346).

// Combine applies changes in order as one Change: one diff, one signature,
// one version. The first error stops it and nothing is signed.
func Combine(changes ...Change) Change {
	return func(doc *trust.Document) error {
		for _, c := range changes {
			if err := c(doc); err != nil {
				return err
			}
		}
		return nil
	}
}

// MaxBulkDevices bounds one bulk membership change.
const MaxBulkDevices = trust.MaxDevices

// BulkOp is a membership operation applied to many devices (#362).
type BulkOp struct {
	// Extend sets every membership to end this long after now (0: no).
	Extend time.Duration
	// Expire ends every membership now.
	Expire bool
	// AddTags and RemoveTags edit every device's tags.
	AddTags    []string
	RemoveTags []string
}

// BulkMembership returns one Change that applies op to every named device.
// An unknown name fails the whole change.
func BulkMembership(names []string, op BulkOp, now time.Time) (Change, error) {
	if len(names) == 0 || len(names) > MaxBulkDevices {
		return nil, fmt.Errorf("choose between 1 and %d devices", MaxBulkDevices)
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			return nil, fmt.Errorf("device %q is listed twice", n)
		}
		seen[n] = true
	}
	if op.Extend > 0 && op.Expire {
		return nil, errors.New("extend and expire cannot be combined")
	}
	if op.Extend == 0 && !op.Expire && len(op.AddTags) == 0 && len(op.RemoveTags) == 0 {
		return nil, errors.New("nothing to do")
	}
	return func(doc *trust.Document) error {
		for _, name := range names {
			d, ok := doc.DeviceByName(name)
			if !ok {
				return fmt.Errorf("%w: %s", trust.ErrUnknownDevice, name)
			}
			switch {
			case op.Extend > 0:
				if _, err := doc.ExtendDevice(name, now, op.Extend); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			case op.Expire:
				if _, err := doc.ExpireDevice(name, now); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
			if len(op.AddTags) > 0 || len(op.RemoveTags) > 0 {
				tags := slices.Clone(d.Tags)
				for _, t := range op.AddTags {
					if !slices.Contains(tags, t) {
						tags = append(tags, t)
					}
				}
				tags = slices.DeleteFunc(tags, func(t string) bool { return slices.Contains(op.RemoveTags, t) })
				if err := doc.SetDeviceTags(name, tags); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
		}
		return nil
	}, nil
}

// SetLockdown returns a Change that turns the emergency lock on or off.
func SetLockdown(on bool, reason string, now time.Time) Change {
	return func(doc *trust.Document) error { return doc.SetLockdown(on, reason, now) }
}

// SetMaxKeyAge returns a Change that sets the key age policy (0: none).
func SetMaxKeyAge(days int) Change {
	return func(doc *trust.Document) error { return doc.SetMaxKeyAge(days) }
}

// CompactRevocations returns a Change that keeps the newest keep
// revocations in full and compacts the rest.
func CompactRevocations(keep int) Change {
	return func(doc *trust.Document) error {
		n, err := doc.CompactRevocations(keep)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("there are no revocations to compact")
		}
		return nil
	}
}

// p01Changes describes the P01 fields for the diff.
func p01Changes(prev, next *trust.Document) []string {
	var out []string
	switch {
	case prev.Lockdown == nil && next.Lockdown != nil:
		line := "ACİL KİLİT: açıldı (bütün kurallar askıda; yalnızca yönetici cihazlar erişebilir)"
		if next.Lockdown.Reason != "" {
			line += " — " + next.Lockdown.Reason
		}
		out = append(out, line)
	case prev.Lockdown != nil && next.Lockdown == nil:
		out = append(out, "Acil kilit: kaldırıldı (kurallar aynen geri döner)")
	}
	if prev.MaxKeyAgeDays != next.MaxKeyAgeDays {
		if next.MaxKeyAgeDays == 0 {
			out = append(out, "Anahtar yaşı politikası: kaldırıldı")
		} else {
			out = append(out, fmt.Sprintf("Anahtar yaşı politikası: en çok %d gün", next.MaxKeyAgeDays))
		}
	}
	if a, b := len(prev.RevokedKeyDigests), len(next.RevokedKeyDigests); a != b {
		out = append(out, fmt.Sprintf("Sıkıştırılmış iptal: %d → %d anahtar özeti", a, b))
	}
	if newP01Field(prev, next) {
		out = append(out, "UYARI: bu sürüm yeni belge alanı kullanıyor; ADR-0151 öncesi cihazlar ve koordinatör onu reddeder")
	}
	return out
}

func usesP01(doc *trust.Document) bool {
	return doc.Lockdown != nil || doc.MaxKeyAgeDays != 0 || len(doc.RevokedKeyDigests) != 0
}

func newP01Field(prev, next *trust.Document) bool { return !usesP01(prev) && usesP01(next) }

// describeP01 gives the Turkish messages of the P01 errors.
func describeP01(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrNoDraft):
		return "Bekleyen değişiklik taslağı yok.", true
	case errors.Is(err, ErrDraftStale):
		return "Taslak başladıktan sonra ağ belgesi imzalandı; taslağı silip yeniden hazırlayın.", true
	case errors.Is(err, ErrLedgerBroken):
		return "İmza defterinin karma zinciri bozuk: defter elle değiştirilmiş veya kesilmiş olabilir.", true
	}
	return "", false
}
