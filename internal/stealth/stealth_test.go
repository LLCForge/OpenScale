package stealth

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The #247 condition: the mode can never disable the kill switch or leak
// protection. These tests are the proof the ADR refers to.

func TestApplyNeverChangesProtections(t *testing.T) {
	n := reflect.TypeFor[Settings]().NumField()
	pn := reflect.TypeFor[Protections]().NumField()
	for sm := 0; sm < 1<<n; sm++ {
		var s Settings
		sv := reflect.ValueOf(&s).Elem()
		for i := range n {
			sv.Field(i).SetBool(sm&(1<<i) != 0)
		}
		for pm := 0; pm < 1<<pn; pm++ {
			var p Protections
			pv := reflect.ValueOf(&p).Elem()
			for i := range pn {
				pv.Field(i).SetBool(pm&(1<<i) != 0)
			}
			if got := s.Apply(p); got != p {
				t.Fatalf("settings %+v changed protections %+v to %+v", s, p, got)
			}
		}
	}
}

func TestSettingsStayCosmetic(t *testing.T) {
	allowed := map[string]bool{"HideTray": true, "QuietNotifications": true}
	typ := reflect.TypeFor[Settings]()
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !allowed[f.Name] || f.Type.Kind() != reflect.Bool {
			t.Fatalf("field %s is not on the cosmetic allowlist; stealth mode must not gain a switch that could touch a protection (ADR-0109)", f.Name)
		}
	}
}

func TestDecodeRefusesProtectionKeys(t *testing.T) {
	for _, in := range []string{
		`{"killswitch":false}`,
		`{"hide_tray":true,"kill_switch":false}`,
		`{"leak_protection":false}`,
		`{"interface_name":"eth9"}`,
		`{"hide_tray":true}{"x":1}`,
	} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%s) accepted", in)
		}
	}
	s, err := Decode([]byte(`{"hide_tray":true,"quiet_notifications":true}`))
	if err != nil || !s.HideTray || !s.QuietNotifications {
		t.Fatalf("Decode = %+v, %v", s, err)
	}
}

func TestLoadSaveAndDamagedFile(t *testing.T) {
	dir := t.TempDir()
	if s, err := Load(dir); err != nil || s.Enabled() {
		t.Fatalf("default = %+v, %v", s, err)
	}
	if err := Save(dir, Settings{HideTray: true}); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(dir); err != nil || !s.HideTray {
		t.Fatalf("Load = %+v, %v", s, err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"hide_tray":true,"killswitch":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(dir); err == nil || s.Enabled() {
		t.Fatalf("damaged file: %+v, %v", s, err)
	}
	if err := Save(dir, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatalf("off did not remove the file: %v", err)
	}
}

// TestImportsCannotReachProtections keeps the package unable to call into
// the code that runs the kill switch, filters or the tunnel.
func TestImportsCannotReachProtections(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"github.com/openscale/openscale/internal/securefile": true}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(p, ".") && !allowed[p] {
				t.Errorf("%s imports %s; stealth may only import the standard library and securefile", f, p)
			}
		}
	}
}
