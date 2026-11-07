package osnet

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLookToolUsesSystemFolders(t *testing.T) {
	name := "ip"
	if runtime.GOOS == "windows" {
		name = "netsh"
	}
	p, err := lookTool(name)
	if errors.Is(err, errToolNotFound) && runtime.GOOS != "windows" {
		t.Skipf("%s not installed here", name)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) {
		t.Fatalf("path %q is not absolute", p)
	}
	cmd, err := toolCommand(context.Background(), name, "help")
	if err != nil || cmd.Path != p || len(cmd.Env) == 0 {
		t.Fatalf("command = %+v, %v", cmd, err)
	}
}

func TestLookToolRefusesPaths(t *testing.T) {
	for _, name := range []string{"", "../ip", "/tmp/ip", `C:\x\netsh.exe`, "openscale-no-such-tool"} {
		if _, err := lookTool(name); !errors.Is(err, errToolNotFound) {
			t.Errorf("lookTool(%q) = %v", name, err)
		}
	}
}
