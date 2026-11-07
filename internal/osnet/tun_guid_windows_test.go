//go:build windows

package osnet

import "testing"

func TestAdapterGUIDIsStablePerName(t *testing.T) {
	a, b := adapterGUID("OpenScale"), adapterGUID("openscale")
	if *a != *b {
		t.Fatal("the GUID must not depend on letter case")
	}
	if *a == *adapterGUID("OpenScale2") {
		t.Fatal("different names must get different GUIDs")
	}
	if a.Data3>>12 != 5 || a.Data4[0]>>6 != 2 {
		t.Fatalf("not a version 5 layout: %s", a.String())
	}
}
