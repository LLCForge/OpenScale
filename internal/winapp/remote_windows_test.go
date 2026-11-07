//go:build windows

package winapp

import (
	"net/netip"
	"strings"
	"testing"
)

// Read-only: queries the firewall and listeners, changes nothing.
func TestRemoteAccessReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PowerShell")
	}
	st, err := GetRemoteAccess()
	if err != nil {
		t.Fatalf("GetRemoteAccess: %v", err)
	}
	if st.RDPPort < 1 || st.SSHPort < 1 {
		t.Fatalf("ports %+v", st)
	}
	ls, err := ListeningPorts()
	if err != nil {
		t.Fatalf("ListeningPorts: %v", err)
	}
	if len(ls) == 0 {
		t.Fatal("no listeners at all")
	}
	t.Logf("status %+v, %d listeners, first %+v", st, len(ls), ls[0])
}

func TestRemoteListQuoting(t *testing.T) {
	got, err := remoteList([]netip.Prefix{netip.MustParsePrefix("100.80.0.0/16"), netip.MustParsePrefix("fde6:1f40:8c2::/48")})
	if err != nil || got != "'100.80.0.0/16','fde6:1f40:8c2::/48'" {
		t.Fatalf("remoteList = %q, %v", got, err)
	}
	if _, err := remoteList(nil); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := remoteList([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); err == nil {
		t.Fatal("whole internet accepted")
	}
	if strings.Contains(psList([]string{"a"}), "\"") {
		t.Fatal("psList quoting")
	}
}
