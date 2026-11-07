// Package dohcheck finds browsers configured to resolve names with their
// own DNS over HTTPS resolver (#94, ADR-0102). Such a browser bypasses the
// tunnel's resolver: MagicDNS names fail in it and, with an exit node, its
// queries go to a third party instead of the exit node.
//
// The check only reads local browser settings files (Firefox prefs.js,
// Chromium-family "Local State"); it sends nothing anywhere. A finding
// names the browser, the profile folder, the mode and the resolver's host
// name, never the full template (it may hold an account identifier).
//
// Browsers that turn DoH on by themselves (Firefox's default rollout) are
// handled on the resolver side instead: the exit node answers Firefox's
// canary name with NXDOMAIN (node/exitdns_policy.go).
package dohcheck

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Finding is one browser profile whose DNS setting bypasses the system
// resolver.
type Finding struct {
	Browser string `json:"browser"`
	Profile string `json:"profile"`
	// Mode is the browser's own name of the setting ("2", "3" for Firefox;
	// "secure", "automatic" for Chromium).
	Mode string `json:"mode"`
	// Resolver is the DoH server's host name, "" when the browser's
	// default provider is used.
	Resolver string `json:"resolver,omitempty"`
	// Bypass is true when queries certainly skip the system resolver;
	// false marks a setting that may (fallback modes).
	Bypass bool `json:"bypass"`
}

// maxSettingsFile bounds the settings files read.
const maxSettingsFile = 32 << 20

// Dirs are the base folders searched.
type Dirs struct {
	// Home is the user's home folder.
	Home string
	// AppData and LocalAppData are the Windows roaming and local folders.
	AppData, LocalAppData string
	// Config is the XDG configuration folder (Linux, BSD).
	Config string
	// GOOS selects the layout; "" uses the running system's.
	GOOS string
}

// DefaultDirs returns the current user's folders.
func DefaultDirs() Dirs {
	d := Dirs{GOOS: runtime.GOOS}
	d.Home, _ = os.UserHomeDir()
	d.AppData = os.Getenv("APPDATA")
	d.LocalAppData = os.Getenv("LOCALAPPDATA")
	d.Config, _ = os.UserConfigDir()
	return d
}

// Scan checks the current user's browsers.
func Scan() ([]Finding, error) { return ScanDirs(DefaultDirs()) }

// ScanDirs checks the browsers below d. Unreadable profiles are skipped;
// an error is returned only when nothing could be read and something
// failed.
func ScanDirs(d Dirs) ([]Finding, error) {
	goos := d.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	var out []Finding
	var errs []error
	for _, fx := range firefoxRoots(d, goos) {
		profiles, _ := filepath.Glob(filepath.Join(fx, "*", "prefs.js"))
		for _, p := range profiles {
			f, err := firefoxProfile(p)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if f != nil {
				out = append(out, *f)
			}
		}
	}
	for _, c := range chromiumRoots(d, goos) {
		f, err := chromiumLocalState(c.browser, filepath.Join(c.dir, "Local State"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Browser != out[j].Browser {
			return out[i].Browser < out[j].Browser
		}
		return out[i].Profile < out[j].Profile
	})
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func firefoxRoots(d Dirs, goos string) []string {
	var out []string
	switch goos {
	case "windows":
		if d.AppData != "" {
			out = append(out, filepath.Join(d.AppData, "Mozilla", "Firefox", "Profiles"))
		}
	case "darwin":
		if d.Home != "" {
			out = append(out, filepath.Join(d.Home, "Library", "Application Support", "Firefox", "Profiles"))
		}
	default:
		if d.Home != "" {
			out = append(out,
				filepath.Join(d.Home, ".mozilla", "firefox"),
				filepath.Join(d.Home, "snap", "firefox", "common", ".mozilla", "firefox"),
				filepath.Join(d.Home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"))
		}
	}
	return out
}

type chromium struct{ browser, dir string }

func chromiumRoots(d Dirs, goos string) []chromium {
	var out []chromium
	switch goos {
	case "windows":
		if d.LocalAppData != "" {
			for _, c := range []chromium{
				{"Chrome", filepath.Join("Google", "Chrome", "User Data")},
				{"Edge", filepath.Join("Microsoft", "Edge", "User Data")},
				{"Brave", filepath.Join("BraveSoftware", "Brave-Browser", "User Data")},
				{"Chromium", filepath.Join("Chromium", "User Data")},
				{"Vivaldi", filepath.Join("Vivaldi", "User Data")},
			} {
				out = append(out, chromium{c.browser, filepath.Join(d.LocalAppData, c.dir)})
			}
		}
	case "darwin":
		if d.Home != "" {
			base := filepath.Join(d.Home, "Library", "Application Support")
			for _, c := range []chromium{
				{"Chrome", filepath.Join("Google", "Chrome")},
				{"Edge", "Microsoft Edge"},
				{"Brave", filepath.Join("BraveSoftware", "Brave-Browser")},
				{"Chromium", "Chromium"},
				{"Vivaldi", "Vivaldi"},
			} {
				out = append(out, chromium{c.browser, filepath.Join(base, c.dir)})
			}
		}
	default:
		if d.Config != "" {
			for _, c := range []chromium{
				{"Chrome", "google-chrome"},
				{"Edge", "microsoft-edge"},
				{"Brave", filepath.Join("BraveSoftware", "Brave-Browser")},
				{"Chromium", "chromium"},
				{"Vivaldi", "vivaldi"},
			} {
				out = append(out, chromium{c.browser, filepath.Join(d.Config, c.dir)})
			}
		}
	}
	return out
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSettingsFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSettingsFile {
		return nil, errors.New("ayar dosyası çok büyük: " + filepath.Base(path))
	}
	return b, nil
}

var (
	trrModeRe = regexp.MustCompile(`user_pref\("network\.trr\.mode",\s*(\d+)\);`)
	trrURIRe  = regexp.MustCompile(`user_pref\("network\.trr\.(?:custom_)?uri",\s*"([^"]{0,1000})"\);`)
)

// firefoxProfile reads network.trr.mode: 2 uses DoH first and falls back
// to the system resolver, 3 uses only DoH (RFC 8484 resolver of the
// browser's choice).
func firefoxProfile(prefs string) (*Finding, error) {
	b, err := readLimited(prefs)
	if err != nil {
		return nil, err
	}
	m := trrModeRe.FindSubmatch(b)
	if m == nil {
		return nil, nil
	}
	mode := string(m[1])
	if mode != "2" && mode != "3" {
		return nil, nil
	}
	f := &Finding{Browser: "Firefox", Profile: filepath.Base(filepath.Dir(prefs)), Mode: mode, Bypass: mode == "3"}
	if u := trrURIRe.FindAllSubmatch(b, -1); len(u) > 0 {
		f.Resolver = hostOf(string(u[len(u)-1][1]))
	}
	return f, nil
}

// chromiumLocalState reads dns_over_https.mode: "secure" always uses the
// configured DoH server; "automatic" upgrades only when the system's
// resolver is a known DoH provider, which may happen with custom
// templates.
func chromiumLocalState(browser, path string) (*Finding, error) {
	b, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	var st struct {
		DoH struct {
			Mode      string `json:"mode"`
			Templates string `json:"templates"`
		} `json:"dns_over_https"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, errors.New(browser + " ayar dosyası okunamadı")
	}
	mode := strings.ToLower(st.DoH.Mode)
	switch {
	case mode == "secure":
	case mode == "automatic" && strings.TrimSpace(st.DoH.Templates) != "":
	default:
		return nil, nil
	}
	f := &Finding{Browser: browser, Profile: "Local State", Mode: mode, Bypass: mode == "secure"}
	if t := strings.Fields(st.DoH.Templates); len(t) > 0 {
		f.Resolver = hostOf(t[0])
	}
	return f, nil
}

// hostOf keeps only the host of a DoH template.
func hostOf(tmpl string) string {
	u, err := url.Parse(strings.ReplaceAll(strings.ReplaceAll(tmpl, "{", ""), "}", ""))
	if err != nil {
		return ""
	}
	return u.Hostname()
}
