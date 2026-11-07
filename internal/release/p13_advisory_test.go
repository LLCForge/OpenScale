package release

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func sampleAdvisories() Advisories {
	return Advisories{Sequence: 3, Advisories: []Advisory{
		{ID: "OSA-2026-0001", Severity: SeverityHigh, Title: "Süzgeçte port aralığı hatası", Introduced: "0.8.0", Fixed: "0.9.1", Published: t0},
		{ID: "OSA-2026-0002", Severity: SeverityCritical, Title: "Henüz düzeltilmedi", Summary: "Satır 1\nSatır 2", Introduced: "0.9.0", Published: t0},
	}}
}

func TestAdvisories(t *testing.T) {
	root, priv, _ := GenerateKey(rand.Reader)
	data, err := SignAdvisories(priv, sampleAdvisories(), t0)
	if err != nil {
		t.Fatal(err)
	}
	a, err := VerifyAdvisories(root, data, 3)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"0.7.9":        nil,
		"0.8.0":        {"OSA-2026-0001"},
		"0.9.0-rc.1":   {"OSA-2026-0001"},
		"0.9.0":        {"OSA-2026-0001", "OSA-2026-0002"},
		"0.9.1":        {"OSA-2026-0002"},
		"1.0.0+build7": {"OSA-2026-0002"},
	}
	for v, want := range cases {
		got, err := a.Affecting(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		var ids []string
		for _, g := range got {
			ids = append(ids, g.ID)
		}
		if len(ids) != len(want) || (len(ids) > 0 && ids[0] != want[0]) || (len(ids) > 1 && ids[1] != want[1]) {
			t.Errorf("%s: %v, want %v", v, ids, want)
		}
	}
	if _, err := a.Affecting("not-a-version"); err == nil {
		t.Error("unparsable version reported as unaffected")
	}

	// Older list, other root, tampering, revocation context.
	if _, err := VerifyAdvisories(root, data, 4); !errors.Is(err, ErrStaleAdvisories) {
		t.Errorf("stale list: %v", err)
	}
	other, _, _ := GenerateKey(rand.Reader)
	if _, err := VerifyAdvisories(other, data, 0); err == nil {
		t.Error("verified with another root")
	}
	if _, err := VerifyAdvisories(root, bytes.Replace(data, []byte(`"payload": "`), []byte(`"payload": "A`), 1), 0); err == nil {
		t.Error("tampered list verified")
	}
	rev, _ := SignRevocations(priv, Revocations{Sequence: 1, Issued: t0})
	if _, err := VerifyAdvisories(root, rev, 0); err == nil {
		t.Error("revocation list accepted as advisories")
	}
}

func TestAdvisoryValidation(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	mut := []func(*Advisories){
		func(a *Advisories) { a.Sequence = 0 },
		func(a *Advisories) { a.Advisories[0].ID = "osa-1" },
		func(a *Advisories) { a.Advisories[0].Severity = "urgent" },
		func(a *Advisories) { a.Advisories[0].Title = "" },
		func(a *Advisories) { a.Advisories[0].Title = "a\x1bb" },
		func(a *Advisories) { a.Advisories[0].Fixed = "0.8.0" },
		func(a *Advisories) { a.Advisories[0].Introduced = "v1" },
		func(a *Advisories) { a.Advisories[1].ID = a.Advisories[0].ID },
		func(a *Advisories) { a.Advisories[0].Published = time.Time{} },
	}
	for i, m := range mut {
		a := sampleAdvisories()
		m(&a)
		if _, err := SignAdvisories(priv, a, t0); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func FuzzVerifyAdvisories(fz *testing.F) {
	root, priv, _ := GenerateKey(rand.Reader)
	data, err := SignAdvisories(priv, sampleAdvisories(), t0)
	if err != nil {
		fz.Fatal(err)
	}
	fz.Add(data)
	fz.Add([]byte(`{"context":"openscale/release-advisories/v1","payload":"e30=","signature":"AA=="}`))
	fz.Fuzz(func(t *testing.T, b []byte) {
		a, err := VerifyAdvisories(root, b, 0)
		if err != nil {
			return
		}
		for _, adv := range a.Advisories {
			if _, err := a.Affecting(adv.Introduced); err != nil {
				t.Fatal(err)
			}
		}
	})
}
