package privsep

import "testing"

func TestParseProcStatus(t *testing.T) {
	in := "Name:\topenscale\nUid:\t0\t65534\t65534\t65534\nGid:\t0\t0\t0\t0\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\n"
	ps := parseProcStatus(in)
	if !ps.ok || ps.euid != 65534 || !ps.noNewPrivs || ps.capEff != 0 {
		t.Fatalf("parse = %+v", ps)
	}
	root := parseProcStatus("Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t0\n")
	if !root.ok || root.euid != 0 || root.noNewPrivs || root.capEff == 0 {
		t.Fatalf("root parse = %+v", root)
	}
	if parseProcStatus("garbage").ok {
		t.Fatal("garbage parsed")
	}
}

func TestIntegrityName(t *testing.T) {
	for rid, want := range map[uint32]string{0: "untrusted", 0x1000: "low", 0x2000: "medium", 0x2100: "medium", 0x3000: "high", 0x4000: "system"} {
		if got := integrityName(rid); got != want {
			t.Errorf("integrityName(%#x) = %q", rid, got)
		}
	}
}

// TestCurrentStatusReadOnly only reads the current process's rights.
func TestCurrentStatusReadOnly(t *testing.T) {
	if st := CurrentStatus(); st.Summary == "" {
		t.Fatal("empty summary")
	}
}
