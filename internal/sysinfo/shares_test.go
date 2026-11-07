package sysinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

const testparmOut = `# Global parameters
[global]
	server role = standalone server
	workgroup = WORKGROUP

[homes]
	browseable = No
	comment = Home Directories

[printers]
	path = /var/spool/samba
	printable = Yes

[print$]
	path = /var/lib/samba/printers

[Delta]
	comment = Ana disk
	path = /srv/delta
	read only = No

[gizli]
	browseable = no
	path = /srv/gizli

[yedek$]
	path = /srv/yedek

[kapali]
	available = no
	path = /srv/kapali

[Lazer]
	print ok = yes

; a comment
[Müzik]
	comment = Şarkılar \
	  ve albümler
	path = /srv/muzik

[../etc]
	path = /etc
`

func TestParseSambaConfig(t *testing.T) {
	got := normalizeShares(ParseSambaConfig(strings.NewReader(testparmOut)))
	want := []Share{{Name: "Delta", Comment: "Ana disk"}, {Name: "Müzik", Comment: "Şarkılar ve albümler"}}
	if len(got) != len(want) {
		t.Fatalf("shares = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("share %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for _, s := range got {
		if strings.Contains(s.Comment, "/srv") {
			t.Fatal("a path leaked into the report")
		}
	}
}

func TestParseUsershareList(t *testing.T) {
	got := normalizeShares(ParseUsershareList(strings.NewReader("filmler\n\nbelgeler\ngizli$\nkötü/ad\n")))
	if len(got) != 2 || got[0].Name != "belgeler" || got[1].Name != "filmler" {
		t.Fatalf("usershares = %+v", got)
	}
}

func TestValidShareName(t *testing.T) {
	for _, ok := range []string{"Delta", "programs", "Müzik", "yedek-2026", "a.b_c d", "İş"} {
		if !ValidShareName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "..", "a..b", `a\b`, "a/b", "c:", "C$", ".gizli", "son.", " bas", "son ",
		"CON", "nul.txt", "com1", "a\x00b", "a\nb", "a*b", "a?b", `a"b`, "a<b", "a|b", "a%b",
		strings.Repeat("x", 81), "‮kötü", "a​b"} {
		if ValidShareName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizeSharesLimits(t *testing.T) {
	var in []Share
	for i := range 100 {
		in = append(in, Share{Name: "pay" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Comment: strings.Repeat("ç", 60)})
	}
	in = append(in, Share{Name: "DELTA"}, Share{Name: "delta"})
	got := normalizeShares(in)
	if len(got) != MaxShares {
		t.Fatalf("len = %d, want %d", len(got), MaxShares)
	}
	for _, s := range got {
		if len(s.Comment) > maxShareComment {
			t.Fatalf("comment too long: %d", len(s.Comment))
		}
	}
	dup := normalizeShares([]Share{{Name: "DELTA"}, {Name: "delta"}})
	if len(dup) != 1 {
		t.Fatalf("duplicates kept: %+v", dup)
	}
}

func TestCollectSharesNeedsSMBListener(t *testing.T) {
	oldL, oldS := shareListening, shareList
	t.Cleanup(func() { shareListening, shareList = oldL, oldS })
	shareList = func() []Share { return []Share{{Name: "Delta"}} }
	shareListening = func() []uint16 { return []uint16{22, 80} }
	d := &Detail{}
	collectShares(d)
	if d.Shares != nil {
		t.Fatalf("shares without an SMB listener: %+v", d.Shares)
	}
	shareListening = func() []uint16 { return []uint16{22, 445} }
	collectShares(d)
	if len(d.Shares) != 1 || d.Shares[0].Name != "Delta" {
		t.Fatalf("shares = %+v", d.Shares)
	}
}

func TestDecodeDetailSanitizesShares(t *testing.T) {
	d := Detail{Ver: DetailVersion, Users: -1, Shares: []Share{{Name: `..\..\Windows`}, {Name: "ok", Comment: "a\x07b"}, {Name: "x$"}}}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzipBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDetail(gz, detailID(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Shares) != 1 || got.Shares[0].Name != "ok" || got.Shares[0].Comment != "a b" {
		t.Fatalf("shares = %+v", got.Shares)
	}
}

func FuzzParseSambaConfig(f *testing.F) {
	f.Add(testparmOut)
	f.Fuzz(func(t *testing.T, s string) {
		for _, sh := range normalizeShares(ParseSambaConfig(strings.NewReader(s))) {
			if !ValidShareName(sh.Name) {
				t.Fatalf("invalid name passed: %q", sh.Name)
			}
		}
	})
}
