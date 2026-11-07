package trust

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestRoundTimestamp(t *testing.T) {
	in := time.Date(2026, 10, 30, 12, 34, 56, 789, time.FixedZone("TR", 3*3600))
	got := roundTimestamp(in)
	want := time.Date(2026, 10, 30, 9, 34, 0, 0, time.UTC)
	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("roundTimestamp = %v, want %v", got, want)
	}
	if got.After(in) {
		t.Fatal("rounding moved the time into the future")
	}
}

// TestDocumentTimesAreRoundedToMinute is #49: the issue time of a new
// document carries no seconds.
func TestDocumentTimesAreRoundedToMinute(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 34, 56, 0, time.UTC)
	id, err := NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ula, err := RandomULAPrefix(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := NewDocument(id, DefaultDNSDomain, DefaultIPv4Prefix, ula, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if doc.IssuedAt.Second() != 0 || doc.IssuedAt.Nanosecond() != 0 {
		t.Fatalf("IssuedAt %v has seconds", doc.IssuedAt)
	}
	if !doc.ExpiresAt.Equal(doc.IssuedAt.Add(30 * 24 * time.Hour)) {
		t.Fatalf("ExpiresAt %v not derived from the rounded time", doc.ExpiresAt)
	}
}
