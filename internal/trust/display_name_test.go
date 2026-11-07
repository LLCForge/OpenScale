package trust

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateDisplayName(t *testing.T) {
	good := []string{"Ev ağı", "a", strings.Repeat("ş", MaxDisplayNameLength), "Ofis (İstanbul)"}
	for _, n := range good {
		if err := ValidateDisplayName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	bad := []string{"", " ev", "ev ", "ev\nağı", "ev\x00", "a‮b", strings.Repeat("a", MaxDisplayNameLength+1), "\xff\xfe"}
	for _, n := range bad {
		if err := ValidateDisplayName(n); !errors.Is(err, ErrInvalidDisplayName) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestDisplayNameOptionalAndValidated(t *testing.T) {
	doc := testDisplayDoc(t)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "display_name") {
		t.Fatal("empty display name must not be encoded")
	}
	if err := doc.SetDisplayName("Ev ağı"); err != nil {
		t.Fatal(err)
	}
	if doc.DisplayName != "Ev ağı" {
		t.Fatalf("display name = %q", doc.DisplayName)
	}
	if err := doc.SetDisplayName("bad\tname"); err == nil || doc.DisplayName != "Ev ağı" {
		t.Fatal("invalid name accepted or document changed")
	}
	if err := doc.SetDisplayName(""); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("removing the display name did not restore the encoding")
	}
	doc.DisplayName = "x​y"
	if err := doc.Validate(); err == nil {
		t.Fatal("Validate accepted a format character")
	}
}

func testDisplayDoc(t *testing.T) *Document {
	t.Helper()
	doc, err := newFixture(t).doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
