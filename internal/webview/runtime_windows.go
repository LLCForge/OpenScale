//go:build windows

package webview

import (
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// runtimeKeys are the EdgeUpdate keys below a root that may describe the
// Evergreen runtime.
var runtimeKeys = []string{
	`SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webView2ClientGUID,
	`SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webView2ClientGUID,
	`SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\` + webView2ClientGUID,
	`SOFTWARE\Microsoft\EdgeUpdate\ClientState\` + webView2ClientGUID,
}

func knownFolder(id *windows.KNOWNFOLDERID) string {
	p, err := windows.KnownFolderPath(id, 0)
	if err != nil {
		return ""
	}
	return p
}

// readRuntimeCandidates lists the runtime entries of the registry. A
// per-user install (HKCU) is only considered when this process is not
// elevated: the per-user key and folder are writable without elevation,
// and an elevated process must not load a DLL a normal process chose.
func readRuntimeCandidates() []runtimeCandidate {
	pfx86 := knownFolder(windows.FOLDERID_ProgramFilesX86)
	pf := knownFolder(windows.FOLDERID_ProgramFiles)
	local := knownFolder(windows.FOLDERID_LocalAppData)
	machineBase := ""
	if pfx86 != "" {
		machineBase = filepath.Join(pfx86, "Microsoft", "EdgeWebView", "Application")
	}
	type root struct {
		key     registry.Key
		base    string
		trusted []string
	}
	roots := []root{{registry.LOCAL_MACHINE, machineBase, nonEmpty(pfx86, pf)}}
	if !windows.GetCurrentProcessToken().IsElevated() && local != "" {
		roots = append(roots, root{
			registry.CURRENT_USER,
			filepath.Join(local, "Microsoft", "EdgeWebView", "Application"),
			[]string{local},
		})
	}
	var out []runtimeCandidate
	for _, r := range roots {
		for _, path := range runtimeKeys {
			k, err := registry.OpenKey(r.key, path, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			pv, _, _ := k.GetStringValue("pv")
			loc, _, _ := k.GetStringValue("location")
			k.Close()
			if pv == "" {
				continue
			}
			out = append(out, runtimeCandidate{version: pv, location: loc, base: r.base, trusted: r.trusted})
		}
	}
	return out
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func fileExists(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// findRuntime returns the newest installed WebView2 runtime.
func findRuntime() (runtimeInfo, error) {
	return selectRuntime(readRuntimeCandidates(), runtime.GOARCH, fileExists)
}
