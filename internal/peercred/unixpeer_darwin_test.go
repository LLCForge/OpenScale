//go:build darwin

package peercred

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIdentityFromXucred(t *testing.T) {
	c := &unix.Xucred{Uid: 501, Ngroups: 3, Groups: [16]uint32{20, 80, 12}}
	id, err := identityFromXucred(c, 42, 0)
	if err != nil {
		t.Fatal(err)
	}
	if id.PID != 42 || id.UID != 501 || id.Admin || id.Self || !id.HasGroup(80) || id.HasGroup(0) {
		t.Fatalf("identity = %+v", id)
	}
	for _, bad := range []*unix.Xucred{nil, {Version: 1}, {Ngroups: 17}, {Ngroups: -1}} {
		if _, err := identityFromXucred(bad, 42, 0); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := identityFromXucred(c, 0, 0); err == nil {
		t.Fatal("accepted pid 0")
	}
}

func TestParseProcArgs(t *testing.T) {
	ok := append([]byte{2, 0, 0, 0}, "/Applications/OpenScale.app/Contents/MacOS/openscale\x00\x00\x00openscale\x00app\x00"...)
	p, err := parseProcArgs(ok)
	if err != nil || p != "/Applications/OpenScale.app/Contents/MacOS/openscale" {
		t.Fatalf("path = %q, %v", p, err)
	}
	for _, bad := range [][]byte{nil, {1, 0, 0, 0}, append([]byte{1, 0, 0, 0}, "openscale\x00"...), append([]byte{1, 0, 0, 0}, "\x00x"...)} {
		if _, err := parseProcArgs(bad); err == nil || strings.Contains(err.Error(), "panic") {
			t.Fatalf("accepted %q", bad)
		}
	}
}
