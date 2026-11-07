package usage

import (
	"testing"
	"time"
)

func TestMonthlyAddAndRetention(t *testing.T) {
	m := NewMonthly(2)
	jan := time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC)
	feb := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	mar := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	m.Add("a", 10, jan)
	m.Add("a", 5, jan)
	m.Add("b", 1, feb)
	if got := m.Get("2026-01", "a"); got != 15 {
		t.Fatalf("jan a = %d", got)
	}
	m.Add("c", 7, mar)
	snap := m.Snapshot()
	if len(snap) != 2 || snap[0].Month != "2026-02" || snap[1].Month != "2026-03" {
		t.Fatalf("retention: %+v", snap)
	}
	// Key limit: the third key of a month goes to OtherKey.
	m.Add("d", 1, mar)
	m.Add("e", 2, mar)
	if m.Get("2026-03", OtherKey) != 2 || m.Get("2026-03", "e") != 0 {
		t.Fatalf("other key: %+v", m.Snapshot())
	}
	// Saturation instead of overflow.
	m.Add("c", ^uint64(0), mar)
	if m.Get("2026-03", "c") != ^uint64(0) {
		t.Fatal("no saturation")
	}
	// Ignored input.
	m.Add("", 1, mar)
	m.Add("x", 0, mar)
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	m := NewMonthly(0)
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	m.Add("dev1", 1234, now)
	if !m.Dirty() {
		t.Fatal("not dirty")
	}
	data, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if m.Dirty() {
		t.Fatal("still dirty")
	}
	back, err := Decode(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if back.Get("2026-10", "dev1") != 1234 {
		t.Fatalf("round trip: %+v", back.Snapshot())
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, in := range map[string]string{
		"unknown field": `{"schema":1,"months":[],"x":1}`,
		"schema":        `{"schema":2,"months":[]}`,
		"month":         `{"schema":1,"months":[{"month":"2026-13","bytes":{}}]}`,
		"duplicate":     `{"schema":1,"months":[{"month":"2026-01","bytes":{}},{"month":"2026-01","bytes":{}}]}`,
		"too many":      `{"schema":1,"months":[{"month":"2026-01","bytes":{}},{"month":"2026-02","bytes":{}},{"month":"2026-03","bytes":{}}]}`,
		"empty key":     `{"schema":1,"months":[{"month":"2026-01","bytes":{"":1}}]}`,
		"trailing":      `{"schema":1,"months":[]} {}`,
	} {
		if _, err := Decode([]byte(in), 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"schema":1,"months":[{"month":"2026-01","bytes":{"a":1}}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data, 8)
		if err != nil {
			return
		}
		out, err := m.Encode()
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if _, err := Decode(out, 8); err != nil {
			t.Fatalf("decode of own output: %v", err)
		}
	})
}
