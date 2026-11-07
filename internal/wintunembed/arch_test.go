package wintunembed

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every Windows architecture a release can build (#496: arm64 next to
// amd64) embeds the DLL of its own architecture. A wrong path here would
// load a DLL the CPU cannot run, so the mapping is checked on every OS.
func TestEmbedFilesMatchArchitecture(t *testing.T) {
	dirFor := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "x86", "arm": "arm"}
	re := regexp.MustCompile(`//go:embed dll/([a-z0-9]+)/wintun\.dll`)
	for goarch, dir := range dirFor {
		name := "embed_windows_" + goarch + ".go"
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(data), "//go:build windows && "+goarch+"\n") {
			t.Errorf("%s: build constraint is not windows && %s", name, goarch)
		}
		m := re.FindStringSubmatch(string(data))
		if m == nil || m[1] != dir {
			t.Errorf("%s embeds %v, want dll/%s", name, m, dir)
		}
		if _, err := os.Stat(filepath.Join("dll", dir, "wintun.dll")); err != nil {
			t.Errorf("dll/%s/wintun.dll: %v", dir, err)
		}
	}
}
