package webview

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

// WebView2 runtime discovery (Windows). The pure parts live here so they
// are tested on every system.

// webView2ClientGUID is the Evergreen WebView2 runtime product in the
// EdgeUpdate registry keys.
const webView2ClientGUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

// minRuntimeMajor is the oldest runtime that has every interface the
// window needs (ICoreWebView2_10 for HTTP authentication, _4 for
// downloads, Settings4 for autofill and password saving).
const minRuntimeMajor = 101

// runtimeVersion is a dotted four-part WebView2 version.
type runtimeVersion [4]uint32

func (v runtimeVersion) String() string {
	parts := make([]string, 4)
	for i, p := range v {
		parts[i] = strconv.FormatUint(uint64(p), 10)
	}
	return strings.Join(parts, ".")
}

// parseRuntimeVersion parses "a.b.c.d". "0.0.0.0" (the uninstalled mark)
// and anything else malformed is refused.
func parseRuntimeVersion(s string) (runtimeVersion, bool) {
	var v runtimeVersion
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 4 {
		return v, false
	}
	zero := true
	for i, p := range parts {
		if p == "" || len(p) > 7 || (len(p) > 1 && p[0] == '0') {
			return v, false
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return v, false
		}
		v[i] = uint32(n)
		if n != 0 {
			zero = false
		}
	}
	if zero {
		return v, false
	}
	return v, true
}

func (v runtimeVersion) less(o runtimeVersion) bool {
	for i := range v {
		if v[i] != o[i] {
			return v[i] < o[i]
		}
	}
	return false
}

// runtimeCandidate is one registry entry of an installed runtime.
type runtimeCandidate struct {
	version  string // "pv" value
	location string // "location" value, may be empty
	base     string // default install folder for this registry root
	// trusted lists the folders the runtime DLL may live in for this
	// root; a location outside them is ignored.
	trusted []string
}

// runtimeInfo is the chosen runtime.
type runtimeInfo struct {
	version runtimeVersion
	dll     string
}

var errNoRuntime = errors.New("WebView2 çalışma zamanı bulunamadı")

// archDir is the EBWebView sub folder for a GOARCH.
func archDir(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "x86"
	case "arm64":
		return "arm64"
	}
	return ""
}

// runtimeDLLPath is where EmbeddedBrowserWebView.dll lives for one install.
func runtimeDLLPath(appDir, version, goarch string) string {
	return filepath.Join(appDir, version, "EBWebView", archDir(goarch), "EmbeddedBrowserWebView.dll")
}

// insideDir reports whether path is dir itself or below it (case
// insensitive, as on Windows). Both must be absolute.
func insideDir(path, dir string) bool {
	if dir == "" || !filepath.IsAbs(path) || !filepath.IsAbs(dir) {
		return false
	}
	p := filepath.Clean(path)
	d := filepath.Clean(dir)
	if strings.EqualFold(p, d) {
		return true
	}
	sep := string(filepath.Separator)
	if !strings.HasSuffix(d, sep) {
		d += sep
	}
	return len(p) > len(d) && strings.EqualFold(p[:len(d)], d)
}

// selectRuntime picks the newest usable runtime: a valid version at or
// above minRuntimeMajor, a DLL inside a trusted folder that exists.
func selectRuntime(cands []runtimeCandidate, goarch string, exists func(string) bool) (runtimeInfo, error) {
	if archDir(goarch) == "" {
		return runtimeInfo{}, errors.New("WebView2 bu işlemci mimarisinde desteklenmiyor")
	}
	var best runtimeInfo
	found := false
	for _, c := range cands {
		v, ok := parseRuntimeVersion(c.version)
		if !ok || v[0] < minRuntimeMajor {
			continue
		}
		for _, dir := range []string{c.location, c.base} {
			if dir == "" {
				continue
			}
			dll := runtimeDLLPath(dir, v.String(), goarch)
			trusted := false
			for _, t := range c.trusted {
				if insideDir(dll, t) {
					trusted = true
					break
				}
			}
			if !trusted || !exists(dll) {
				continue
			}
			if !found || best.version.less(v) {
				best = runtimeInfo{version: v, dll: dll}
				found = true
			}
			break
		}
	}
	if !found {
		return runtimeInfo{}, errNoRuntime
	}
	return best, nil
}
