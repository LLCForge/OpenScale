package openscale

import (
	"errors"
	"fmt"
	"slices"
)

// Per-app split tunnel (F-049, P27): VpnService.Builder takes either
// addAllowedApplication (only those apps use the VPN) or
// addDisallowedApplication (those apps bypass it), never both. The app
// itself always bypasses its own VPN (ADR-0101): in "exclude" mode it
// adds its package to the list, in "include" mode it never lists itself.

// App split modes.
const (
	appsAll     = ""
	appsInclude = "include"
	appsExclude = "exclude"
)

// Limits of the app list.
const (
	maxApps       = 256
	maxPackageLen = 255
)

// validPackage reports whether s is an Android package name: two or more
// dot-separated segments of ASCII letters, digits and underscores, each
// starting with a letter.
func validPackage(s string) bool {
	if len(s) == 0 || len(s) > maxPackageLen {
		return false
	}
	segments, start := 0, true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if start {
				return false
			}
			segments++
			start = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			start = false
		case c >= '0' && c <= '9', c == '_':
			if start {
				return false
			}
		default:
			return false
		}
	}
	return !start && segments >= 1
}

func (o *startOptions) checkApps() error {
	switch o.AppsMode {
	case appsAll:
		if len(o.Apps) > 0 {
			return errors.New("uygulama listesi verildi ama bölme kipi seçilmedi")
		}
		return nil
	case appsInclude, appsExclude:
	default:
		return fmt.Errorf("bilinmeyen uygulama kipi %q", o.AppsMode)
	}
	if len(o.Apps) == 0 {
		// "include" with no app would put every app (and this one) in the
		// VPN on Android: refuse rather than loop.
		return errors.New("uygulama bazlı bölmede en az bir uygulama seçilmeli")
	}
	if len(o.Apps) > maxApps {
		return fmt.Errorf("en fazla %d uygulama seçilebilir", maxApps)
	}
	seen := make(map[string]bool, len(o.Apps))
	for _, a := range o.Apps {
		if !validPackage(a) {
			return fmt.Errorf("geçersiz uygulama paket adı %q", a)
		}
		if seen[a] {
			return fmt.Errorf("uygulama iki kez seçildi: %s", a)
		}
		seen[a] = true
	}
	return nil
}

// applyApps copies the validated app list into the plan.
func (o startOptions) applyApps(p *vpnPlan) {
	apps := slices.Clone(o.Apps)
	slices.Sort(apps)
	switch o.AppsMode {
	case appsInclude:
		p.AllowedApps = apps
		p.FullTunnel = false
	case appsExclude:
		p.DisallowedApps = apps
		p.FullTunnel = false
	}
}
