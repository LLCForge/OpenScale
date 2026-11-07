// Package windowsdeploy holds the tests of the Windows packaging files: the
// PowerShell module (#859) and the winget/Scoop manifest templates with
// scripts/package-manifests.sh (#887). Nothing here is shipped as Go code.
package windowsdeploy

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func powershell(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("PowerShell yok")
	return ""
}

func buildFakeCLI(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "openscale-fake")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", exe, "./testdata/fakecli")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake cli: %v\n%s", err, out)
	}
	return exe
}

func readLog(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var args []string
		if err := json.Unmarshal(sc.Bytes(), &args); err != nil {
			t.Fatal(err)
		}
		out = append(out, args)
	}
	return out
}

// moduleScript exercises every function; values come from the environment
// so nothing is quoted into the script.
const moduleScript = `
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $env:MODULE_DIR 'OpenScale.psd1') -Force
$cli = $env:FAKE_CLI
$r = [ordered]@{}
$r.funcs = @(Get-Command -Module OpenScale | ForEach-Object Name | Sort-Object)
$r.running = (Get-OSStatus -CliPath $cli).running
$r.online = @(Get-OSDevice -Online -CliPath $cli | ForEach-Object name)
$r.named = @(Get-OSDevice -Name 't*' -CliPath $cli | ForEach-Object name)
$r.sent = (Send-OSFile -Path $env:ODD_FILE -Device nas -RemoteName 'rapor son.pdf' -CliPath $cli).Device
$r.exit = (Set-OSExitNode -Name ev-sunucu -CliPath $cli).prefs[0].value
$null = Set-OSExitNode -Clear -CliPath $cli
$r.whatif = @(Send-OSFile -Path $env:ODD_FILE -Device nas -CliPath $cli -WhatIf).Count
$r.refused = @()
foreach ($bad in @('nas; calc', 'nas & whoami', '$(whoami)', '-flag', 'a"b')) {
    try { Send-OSFile -Path $env:ODD_FILE -Device $bad -CliPath $cli | Out-Null } catch { $r.refused += $bad }
}
try { Send-OSFile -Path $env:ODD_FILE -Device nas -RemoteName '-x' -CliPath $cli | Out-Null } catch { $r.refused += 'name' }
try { Set-OSExitNode -Name 'x y' -CliPath $cli | Out-Null } catch { $r.refused += 'exit' }
$env:FAKECLI_FAIL = '1'
try { Get-OSStatus -CliPath $cli | Out-Null } catch { $r.failure = $_.Exception.Message }
$env:FAKECLI_FAIL = ''
[System.IO.File]::WriteAllText($env:RESULT, ($r | ConvertTo-Json -Compress -Depth 4), [System.Text.UTF8Encoding]::new($false))
`

// utf8BOM starts the module files: Windows PowerShell 5.1 reads a file
// without it in the ANSI code page and garbles the Turkish messages.
const utf8BOM = "\xef\xbb\xbf"

func TestPowerShellModule(t *testing.T) {
	ps := powershell(t)
	fake := buildFakeCLI(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "argv.log")
	// A file name full of characters a shell would interpret.
	odd := filepath.Join(dir, "a b; $(whoami) & `x' ünlü.txt")
	if err := os.WriteFile(odd, []byte("veri"), 0o600); err != nil {
		t.Fatal(err)
	}
	moduleDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "module-test.ps1")
	if err := os.WriteFile(script, []byte(moduleScript), 0o600); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(dir, "result.json")
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Env = append(os.Environ(), "MODULE_DIR="+moduleDir, "FAKE_CLI="+fake, "FAKECLI_LOG="+logPath, "ODD_FILE="+odd, "FAKECLI_FAIL=", "RESULT="+result)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("powershell: %v\n%s", err, out)
	}
	out, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimPrefix(strings.TrimSpace(string(out)), utf8BOM)
	var r struct {
		Funcs   []string `json:"funcs"`
		Running bool     `json:"running"`
		Online  []string `json:"online"`
		Named   []string `json:"named"`
		Sent    string   `json:"sent"`
		Exit    string   `json:"exit"`
		WhatIf  int      `json:"whatif"`
		Refused []string `json:"refused"`
		Failure string   `json:"failure"`
	}
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if !slices.Equal(r.Funcs, []string{"Get-OSDevice", "Get-OSStatus", "Send-OSFile", "Set-OSExitNode"}) {
		t.Errorf("exported %v", r.Funcs)
	}
	if !r.Running || !slices.Equal(r.Online, []string{"nas"}) || !slices.Equal(r.Named, []string{"tv"}) || r.Sent != "nas" || r.Exit != "ev-sunucu" || r.WhatIf != 0 {
		t.Errorf("results %+v", r)
	}
	if len(r.Refused) != 7 {
		t.Errorf("refused only %v", r.Refused)
	}
	if !strings.Contains(r.Failure, "servise ulaşılamadı") || !strings.Contains(r.Failure, "çıkış kodu 1") {
		t.Errorf("failure message %q", r.Failure)
	}

	calls := readLog(t, logPath)
	want := [][]string{
		{"status", "--json"},
		{"status", "--json"},
		{"status", "--json"},
		{"send", "--name", "rapor son.pdf", "--", odd, "nas"},
		{"set", "--json", "exit-node=ev-sunucu"},
		{"set", "--json", "exit-node="},
		{"status", "--json"}, // the failing call
	}
	if len(calls) != len(want) {
		t.Fatalf("calls %q", calls)
	}
	for i := range want {
		if !slices.Equal(calls[i], want[i]) {
			t.Errorf("call %d: %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestModuleHasNoInvokeExpression(t *testing.T) {
	data, err := os.ReadFile("OpenScale.psm1")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if t := strings.TrimSpace(line); !strings.HasPrefix(t, "#") {
			code = append(code, t)
		}
	}
	src := strings.ToLower(strings.Join(code, "\n"))
	for _, bad := range []string{"invoke-expression", "iex ", "cmd /c", "cmd.exe", "start-process"} {
		if strings.Contains(src, bad) {
			t.Errorf("module uses %q", bad)
		}
	}
	if !strings.HasPrefix(string(data), utf8BOM) {
		t.Error("module needs a UTF-8 BOM for Windows PowerShell 5.1 (Turkish messages)")
	}
}

func bash(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash yok")
	}
	return p
}

func TestPackageManifests(t *testing.T) {
	sh := bash(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	// A throw-away repository copy with only what the script reads.
	work := t.TempDir()
	const version = "9.8.7-beta.6"
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	files := map[string]string{
		"VERSION": version + "\n",
		"dist/" + version + "/SHA256SUMS": hash + "  openscale-" + version + "-windows-amd64.zip\n" +
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  openscale-windows-amd64.exe\n",
	}
	for _, rel := range []string{"scripts/package-manifests.sh", "deploy/windows/scoop/openscale.json"} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		files[rel] = string(data)
	}
	tpls, _ := filepath.Glob(filepath.Join(root, "deploy", "windows", "winget", "*.yaml"))
	if len(tpls) != 3 {
		t.Fatalf("winget templates: %v", tpls)
	}
	for _, p := range tpls {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files["deploy/windows/winget/"+filepath.Base(p)] = string(data)
	}
	for rel, data := range files {
		p := filepath.Join(work, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(env []string, args ...string) (string, error) {
		cmd := exec.Command(sh, append([]string{"scripts/package-manifests.sh"}, args...)...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, bad := range []string{"", "http://ayna.example", "https://ayna.example/a b", "https://ayna.example/x?y=1", "https://ayna.example/x&y", "https://ayna.example/\"x"} {
		if out, err := run([]string{"OPENSCALE_MIRROR=" + bad}); err == nil {
			t.Errorf("mirror %q accepted: %s", bad, out)
		}
	}
	if out, err := run(nil, "--mirror", "https://ayna.example/openscale/", "--version", "1.2"); err == nil {
		t.Errorf("bad version accepted: %s", out)
	}
	out, err := run([]string{"OPENSCALE_MIRROR=https://ayna.example/openscale/"})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	base := filepath.Join(work, "dist", version, "manifests")
	scoop, err := os.ReadFile(filepath.Join(base, "scoop", "openscale.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Version      string `json:"version"`
		Architecture struct {
			X64 struct {
				URL, Hash  string
				ExtractDir string `json:"extract_dir"`
			} `json:"64bit"`
		} `json:"architecture"`
	}
	if err := json.Unmarshal(scoop, &m); err != nil {
		t.Fatalf("scoop JSON: %v\n%s", err, scoop)
	}
	wantURL := "https://ayna.example/openscale/" + version + "/openscale-" + version + "-windows-amd64.zip"
	if m.Version != version || m.Architecture.X64.URL != wantURL || m.Architecture.X64.Hash != hash || m.Architecture.X64.ExtractDir != "openscale-"+version+"-windows-amd64" {
		t.Errorf("scoop %+v", m)
	}
	leftover := regexp.MustCompile(`@[A-Z0-9_]+@`)
	for _, name := range []string{"OpenScale.OpenScale.yaml", "OpenScale.OpenScale.installer.yaml", "OpenScale.OpenScale.locale.tr-TR.yaml"} {
		data, err := os.ReadFile(filepath.Join(base, "winget", version, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		if leftover.MatchString(s) || !strings.Contains(s, "PackageVersion: "+version) {
			t.Errorf("%s not filled:\n%s", name, s)
		}
		if strings.Contains(name, "installer") && (!strings.Contains(s, "InstallerUrl: "+wantURL) || !strings.Contains(s, "InstallerSha256: "+hash)) {
			t.Errorf("installer manifest:\n%s", s)
		}
	}
	// A present archive that does not match the list is refused.
	zip := filepath.Join(work, "dist", version, "openscale-"+version+"-windows-amd64.zip")
	if err := os.WriteFile(zip, []byte("başka içerik"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := run(nil, "--mirror", "https://ayna.example/openscale"); err == nil {
		t.Errorf("mismatching archive accepted: %s", out)
	}
}
