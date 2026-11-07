package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goVersionM = "bin/openscale-linux-arm64: go1.26.0\n" +
	"\tpath\tgithub.com/openscale/openscale/cmd/openscale\n" +
	"\tmod\tgithub.com/openscale/openscale\t(devel)\t\n" +
	"\tdep\tgolang.org/x/crypto\tv0.58.0\th1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=\n" +
	"\tbuild\t-trimpath=true\n" +
	"\tbuild\tCGO_ENABLED=0\n" +
	"\tbuild\tGOARCH=arm64\n" +
	"\tbuild\tGOOS=linux\n"

const lock = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@scope/a':
        specifier: ^1.0.0
        version: 1.0.0(b@2.0.0)
      b:
        specifier: 2.0.0
        version: 2.0.0
    devDependencies:
      eslint:
        specifier: ^9
        version: 9.0.0

packages:

  '@scope/a@1.0.0':
    resolution: {integrity: sha512-` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" + `}
    peerDependencies:
      b: '*'

  b@2.0.0:
    resolution: {integrity: sha512-` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" + `}

  c@3.0.0:
    resolution: {integrity: sha512-` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" + `}

  eslint@9.0.0:
    resolution: {integrity: sha512-` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" + `}

snapshots:

  '@scope/a@1.0.0(b@2.0.0)':
    dependencies:
      b: 2.0.0
      c: 3.0.0

  b@2.0.0: {}

  c@3.0.0: {}

  eslint@9.0.0:
    dependencies:
      c: 3.0.0
`

func TestParseGoVersionM(t *testing.T) {
	bi, err := parseGoVersionM(strings.ReplaceAll(goVersionM, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bi.GoVersion != "go1.26.0" || len(bi.Deps) != 1 || bi.Deps[0].Path != "golang.org/x/crypto" || setting(bi, "GOARCH") != "arm64" {
		t.Fatalf("unexpected build info: %+v", bi)
	}
	if _, err := parseGoVersionM("hello\n"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestParsePnpmLockProductionClosure(t *testing.T) {
	pkgs, err := parsePnpmLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name+"@"+p.Version)
	}
	if got := strings.Join(names, ","); got != "@scope/a@1.0.0,b@2.0.0,c@3.0.0" {
		t.Fatalf("closure = %s", got)
	}
	if pkgs[0].Integrity == "" {
		t.Fatal("integrity missing")
	}
	if _, err := parsePnpmLock("lockfileVersion: '6.0'\n"); err == nil {
		t.Fatal("old lockfile accepted")
	}
}

func TestDeterministicDocument(t *testing.T) {
	dir := t.TempDir()
	mod := filepath.Join(dir, "openscale-linux-arm64.modinfo")
	lockPath := filepath.Join(dir, "pnpm-lock.yaml")
	if err := os.WriteFile(mod, []byte(goVersionM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"-version", "0.9.0", "-source-date-epoch", "1793361600", "-panel-lock", lockPath, mod}
	var a, b bytes.Buffer
	if err := run(args, &a); err != nil {
		t.Fatal(err)
	}
	if err := run(args, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("output is not deterministic")
	}
	var doc spdxDocument
	if err := json.Unmarshal(a.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.CreationInfo.Created != time.Unix(1793361600, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("created = %s", doc.CreationInfo.Created)
	}
	seen := map[string]bool{}
	for _, p := range doc.Packages {
		if seen[p.SPDXID] {
			t.Fatalf("duplicate SPDXID %s", p.SPDXID)
		}
		seen[p.SPDXID] = true
		if p.Name == "eslint" {
			t.Fatal("development dependency included")
		}
	}
	if !strings.Contains(a.String(), "pkg:npm/%40scope/a@1.0.0") || !strings.Contains(a.String(), "pkg:golang/golang.org/x/crypto@v0.58.0") {
		t.Fatal("purl missing")
	}
}

func TestRealLockfile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "panel", "pnpm-lock.yaml"))
	if err != nil {
		t.Skip("panel lockfile not present")
	}
	pkgs, err := parsePnpmLock(string(data))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "next" {
			found = true
		}
		if p.Name == "eslint" || p.Name == "typescript" {
			t.Fatalf("development dependency %s in production closure", p.Name)
		}
	}
	if !found {
		t.Fatal("next missing from the panel closure")
	}
}
