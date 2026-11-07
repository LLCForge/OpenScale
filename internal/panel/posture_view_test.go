package panel

import "testing"

func TestPostureOf(t *testing.T) {
	if postureOf("") != nil {
		t.Fatal("empty report must give nil")
	}
	if postureOf("d=y;x=1") != nil {
		t.Fatal("malformed report must give nil")
	}
	got := postureOf("d=y;f=n;b=26300")
	if got == nil || got.DiskEncryption != "on" || got.Firewall != "off" || got.WindowsBuild != 26300 {
		t.Fatalf("unexpected posture view: %+v", got)
	}
	if v := postureOf("d=u"); v == nil || v.DiskEncryption != "unknown" || v.Firewall != "unknown" {
		t.Fatalf("unknown states: %+v", v)
	}
}
