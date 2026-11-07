package webview

import (
	"path/filepath"
	"testing"
)

func TestParseRuntimeVersion(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"156.0.4314.50", true},
		{" 120.0.2210.91 ", true},
		{"0.0.0.0", false},
		{"", false},
		{"156.0.4314", false},
		{"156.0.4314.50.1", false},
		{"156.0.4314.x", false},
		{"156.0.04314.50", false},
		{"-1.0.0.0", false},
		{"99999999.0.0.0", false},
		{"156..4314.50", false},
	} {
		v, ok := parseRuntimeVersion(tc.in)
		if ok != tc.ok {
			t.Errorf("parseRuntimeVersion(%q) = %v, %v", tc.in, v, ok)
		}
	}
	a, _ := parseRuntimeVersion("120.0.2210.91")
	b, _ := parseRuntimeVersion("120.0.2210.133")
	if !a.less(b) || b.less(a) || a.less(a) {
		t.Error("sürüm karşılaştırması yanlış")
	}
}

func TestSelectRuntime(t *testing.T) {
	root := filepath.Join(string(filepath.Separator)+"pf86", "Microsoft", "EdgeWebView", "Application")
	if v := filepath.VolumeName(absBase(t)); v != "" {
		root = v + root
	}
	pf86 := filepath.Dir(filepath.Dir(filepath.Dir(root)))
	user := filepath.Join(filepath.Dir(pf86), "user", "local")
	userApp := filepath.Join(user, "Microsoft", "EdgeWebView", "Application")
	evil := filepath.Join(filepath.Dir(pf86), "evil")

	present := map[string]bool{
		runtimeDLLPath(root, "120.0.2210.91", "amd64"):    true,
		runtimeDLLPath(root, "156.0.4314.50", "amd64"):    true,
		runtimeDLLPath(userApp, "160.0.1.1", "amd64"):     true,
		runtimeDLLPath(evil, "999.0.0.1", "amd64"):        true,
		runtimeDLLPath(root, "100.0.1185.36", "amd64"):    true,
		runtimeDLLPath(root, "156.0.4314.50", "arm64"):    true,
		runtimeDLLPath(root, "156.0.4314.50", "386"):      false,
		runtimeDLLPath(root, "170.0.1.1", "amd64"):        false,
		runtimeDLLPath(userApp, "156.0.4314.50", "amd64"): false,
	}
	exists := func(p string) bool { return present[p] }
	machine := func(pv, loc string) runtimeCandidate {
		return runtimeCandidate{version: pv, location: loc, base: root, trusted: []string{pf86}}
	}

	got, err := selectRuntime([]runtimeCandidate{
		machine("120.0.2210.91", root),
		machine("156.0.4314.50", ""),
		machine("170.0.1.1", root),     // DLL missing
		machine("100.0.1185.36", root), // too old
		machine("999.0.0.1", evil),     // location outside the trusted folder; base lacks it
		machine("0.0.0.0", root),       // uninstalled
		machine("not-a-version", root), // malformed
	}, "amd64", exists)
	if err != nil || got.version.String() != "156.0.4314.50" || got.dll != runtimeDLLPath(root, "156.0.4314.50", "amd64") {
		t.Fatalf("selectRuntime = %+v, %v", got, err)
	}

	// A per-user install wins when it is newer and inside its folder.
	got, err = selectRuntime([]runtimeCandidate{
		machine("156.0.4314.50", root),
		{version: "160.0.1.1", base: userApp, trusted: []string{user}},
	}, "amd64", exists)
	if err != nil || got.version.String() != "160.0.1.1" {
		t.Fatalf("kullanıcı kurulumu seçilmedi: %+v, %v", got, err)
	}

	// The per-user folder is not trusted for a machine entry.
	if _, err := selectRuntime([]runtimeCandidate{{version: "160.0.1.1", location: userApp, trusted: []string{pf86}}}, "amd64", exists); err == nil {
		t.Error("güvenilmeyen klasördeki DLL seçildi")
	}
	if _, err := selectRuntime(nil, "amd64", exists); err != errNoRuntime {
		t.Errorf("boş liste: %v", err)
	}
	if _, err := selectRuntime([]runtimeCandidate{machine("156.0.4314.50", root)}, "386", exists); err != errNoRuntime {
		t.Errorf("x86 DLL yokken: %v", err)
	}
	if _, err := selectRuntime([]runtimeCandidate{machine("156.0.4314.50", root)}, "riscv64", exists); err == nil {
		t.Error("desteklenmeyen mimari kabul edildi")
	}
	if got, err := selectRuntime([]runtimeCandidate{machine("156.0.4314.50", root)}, "arm64", exists); err != nil ||
		filepath.Base(filepath.Dir(got.dll)) != "arm64" {
		t.Errorf("arm64: %+v, %v", got, err)
	}
}

func TestInsideDir(t *testing.T) {
	base := absBase(t)
	a := filepath.Join(base, "Program Files (x86)")
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{filepath.Join(a, "Microsoft", "x.dll"), true},
		{a, true},
		{filepath.Join(base, "Program Files (x86)evil", "x.dll"), false},
		{filepath.Join(a, "..", "evil", "x.dll"), false},
		{"x.dll", false},
	} {
		if got := insideDir(tc.p, a); got != tc.want {
			t.Errorf("insideDir(%q) = %v", tc.p, got)
		}
	}
	if insideDir(filepath.Join(a, "x"), "") {
		t.Error("boş klasör kabul edildi")
	}
}

// absBase is an absolute path used only as a name; nothing is created
// (tests never write to the system temporary folder).
func absBase(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("yalnizca-ad")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
