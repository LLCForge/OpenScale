package sysinfo

import (
	"encoding/json"
	"testing"

	"github.com/openscale/openscale/internal/posture"
)

func TestPostureExtField(t *testing.T) {
	in := Info{Version: "1", OS: "windows", Posture: "d=y;f=y", PostureExt: posture.Extended{SecureBoot: posture.On, ScreenLock: posture.On, LockMinutes: 5}.Encode()}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil || out.PostureExt != in.PostureExt || out.Posture != in.Posture {
		t.Fatalf("round trip %+v %v", out, err)
	}
	// A malformed statement is dropped, the rest of the report stays.
	raw := map[string]any{}
	_ = json.Unmarshal(data, &raw)
	raw["pe"] = "sb=?"
	bad, _ := json.Marshal(raw)
	out, err = Decode(bad)
	if err != nil || out.PostureExt != "" || out.Posture == "" {
		t.Fatalf("bad ext: %+v %v", out, err)
	}
	// Older readers: the struct without the field ignores "pe".
	var old struct {
		Posture string `json:"ps"`
	}
	if err := json.Unmarshal(data, &old); err != nil || old.Posture != in.Posture {
		t.Fatal("old reader broke")
	}
}
