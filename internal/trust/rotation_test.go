package trust

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func rotationDoc(t *testing.T) (*Document, *DeviceSecrets) {
	t.Helper()
	f := newFixture(t)
	doc, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	secrets, req := newRequest(t, "laptop")
	if _, err := doc.AddDevice(req, "laptop", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	_, other := newRequest(t, "masaustu")
	if _, err := doc.AddDevice(other, "masaustu", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	return doc, secrets
}

func TestKeyRotationRoundTrip(t *testing.T) {
	doc, old := rotationDoc(t)
	now := testNow.Add(time.Hour)
	next, sr, req, err := old.NewKeyRotation(rand.Reader, doc.NetworkID, now)
	if err != nil {
		t.Fatalf("NewKeyRotation: %v", err)
	}
	if next.DeviceID != old.DeviceID {
		t.Fatal("rotation must keep the device id")
	}
	line, err := EncodeKeyRotation(sr)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeKeyRotation(line)
	if err != nil {
		t.Fatalf("DecodeKeyRotation: %v", err)
	}
	opened, err := OpenKeyRotation(doc, decoded, now)
	if err != nil {
		t.Fatalf("OpenKeyRotation: %v", err)
	}
	if opened.Fingerprint() != req.Fingerprint() {
		t.Fatal("fingerprint mismatch")
	}
	before, _ := doc.DeviceByName("laptop")
	dev, err := doc.ApplyKeyRotation(decoded, now)
	if err != nil {
		t.Fatalf("ApplyKeyRotation: %v", err)
	}
	newSig, newWG, _ := next.PublicKeys()
	if dev.SigningKey != newSig || dev.WireGuardKey != newWG || dev.ID != before.ID || dev.IPv4 != before.IPv4 || dev.Name != "laptop" {
		t.Fatalf("rotated device = %+v", dev)
	}
	if len(doc.RetiredKeys) != 1 || doc.RetiredKeys[0].SigningKey != before.SigningKey {
		t.Fatalf("old keys not retired: %+v", doc.RetiredKeys)
	}

	// Single use: the same request no longer matches the current keys.
	if _, err := doc.ApplyKeyRotation(decoded, now); !errors.Is(err, ErrRotationStale) && !errors.Is(err, ErrBadSignature) {
		t.Fatalf("replay error = %v", err)
	}
	// The old keys can never return, as a device or through a rotation.
	_, revert, _, _ := next.NewKeyRotation(rand.Reader, doc.NetworkID, now)
	if _, err := OpenKeyRotation(doc, revert, now); err != nil {
		t.Fatalf("second rotation with new key: %v", err)
	}
	reenroll := &EnrollmentRequest{DeviceID: strings.Repeat("c", 32), SigningKey: before.SigningKey, WireGuardKey: before.WireGuardKey, CreatedAt: now}
	if _, err := doc.AddDevice(reenroll, "geri", nil, now, DefaultDeviceLife); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("retired key re-enrollment error = %v", err)
	}
	doc.Devices[1].WireGuardKey = before.WireGuardKey
	if err := doc.Validate(); err == nil {
		t.Fatal("a device with a retired key must be rejected")
	}
}

func TestKeyRotationRejections(t *testing.T) {
	doc, old := rotationDoc(t)
	now := testNow.Add(time.Hour)
	_, sr, _, err := old.NewKeyRotation(rand.Reader, doc.NetworkID, now)
	if err != nil {
		t.Fatal(err)
	}

	// Expired and future-dated.
	if _, err := OpenKeyRotation(doc, sr, now.Add(KeyRotationMaxAge+time.Minute)); !errors.Is(err, ErrRotationExpired) {
		t.Fatalf("old request error = %v", err)
	}
	if _, err := OpenKeyRotation(doc, sr, now.Add(-time.Hour)); !errors.Is(err, ErrRotationExpired) {
		t.Fatalf("future request error = %v", err)
	}

	// Tampered payload breaks the old signature.
	tampered := sr
	tampered.Payload = append([]byte(nil), sr.Payload...)
	tampered.Payload[len(tampered.Payload)-3] ^= 1
	if _, err := OpenKeyRotation(doc, tampered, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered error = %v", err)
	}

	// Signed by someone who is not the device.
	stranger, _ := GenerateDeviceSecrets(rand.Reader, testNow)
	stranger.DeviceID = old.DeviceID
	_, forged, _, _ := stranger.NewKeyRotation(rand.Reader, doc.NetworkID, now)
	if _, err := OpenKeyRotation(doc, forged, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged error = %v", err)
	}

	// Missing new-key signature (no proof of possession).
	noPoP := sr
	noPoP.NewSignature = make([]byte, len(sr.NewSignature))
	if _, err := OpenKeyRotation(doc, noPoP, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("missing new signature error = %v", err)
	}

	// Another network.
	_, other, _, _ := old.NewKeyRotation(rand.Reader, strings.Repeat("d", 32), now)
	if _, err := OpenKeyRotation(doc, other, now); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("wrong network error = %v", err)
	}

	// Outer device id pointing at a different device.
	swapped := sr
	m, _ := doc.DeviceByName("masaustu")
	swapped.DeviceID = m.ID
	if _, err := OpenKeyRotation(doc, swapped, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("swapped device error = %v", err)
	}

	// Unknown device.
	unknown := sr
	unknown.DeviceID = strings.Repeat("e", 32)
	if _, err := OpenKeyRotation(doc, unknown, now); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown device error = %v", err)
	}

	// Signature context separation: an enrollment signature is not a
	// rotation signature.
	env, _, _ := old.NewEnrollmentRequest("pc", now)
	mixed := SignedKeyRotation{DeviceID: old.DeviceID, Payload: env.Payload, OldSignature: env.Signature, NewSignature: env.Signature}
	if _, err := OpenKeyRotation(doc, mixed, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("cross-context error = %v", err)
	}

	if _, _, _, err := old.NewKeyRotation(rand.Reader, "bad", now); err == nil {
		t.Fatal("invalid network id must be rejected")
	}
	for _, line := range []string{"", "osrot1.", "osrot1.!!!", "osreq1.e30", "osrot1." + strings.Repeat("A", maxRotationChars)} {
		if _, err := DecodeKeyRotation(line); err == nil {
			t.Errorf("DecodeKeyRotation(%.20q) should fail", line)
		}
	}
	if len(doc.RetiredKeys) != 0 {
		t.Fatal("rejected rotations must not change the document")
	}
}

func FuzzDecodeKeyRotation(f *testing.F) {
	s, _ := GenerateDeviceSecrets(rand.Reader, testNow)
	id := strings.Repeat("b", 32)
	_, sr, _, _ := s.NewKeyRotation(rand.Reader, id, testNow)
	line, _ := EncodeKeyRotation(sr)
	f.Add(line)
	f.Add("osrot1.")
	f.Add("osrot1.e30")
	doc := &Document{NetworkID: id, Devices: []Device{{ID: s.DeviceID}}}
	signing, wg, _ := s.PublicKeys()
	doc.Devices[0].SigningKey, doc.Devices[0].WireGuardKey = signing, wg
	f.Fuzz(func(t *testing.T, line string) {
		sr, err := DecodeKeyRotation(line)
		if err != nil {
			return
		}
		req, err := OpenKeyRotation(doc, sr, testNow)
		if err == nil && (req.DeviceID != s.DeviceID || req.OldSigningKey != signing) {
			t.Fatal("accepted a rotation that is not bound to the device")
		}
	})
}
