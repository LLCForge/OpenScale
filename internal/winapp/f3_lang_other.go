//go:build !windows

package winapp

import (
	"context"
	"os"
	"strings"
)

// UITurkish reports whether the session's language is Turkish
// (OPENSCALE_LANG, then LC_ALL, LC_MESSAGES, LANG); without any it stays
// Turkish like the rest of the program.
func UITurkish() bool {
	if v := os.Getenv("OPENSCALE_LANG"); v == "tr" || v == "en" {
		return v == "tr"
	}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			return strings.HasPrefix(strings.ToLower(v), "tr")
		}
	}
	return true
}

// ShowUI has no window outside Windows.
func ShowUI(context.Context, UIKind, UIModel, func() (UIModel, bool)) (UIResult, error) {
	return UIResult{}, ErrNoNativeUI
}

// TrayLeftClick is the Windows tray's choice; elsewhere always the default.
func TrayLeftClick() string { return LeftClickFlyout }

// SetTrayLeftClick exists only on Windows.
func SetTrayLeftClick(choice string) error {
	if choice != LeftClickFlyout && choice != LeftClickPanel {
		return errUnknownLeftClick
	}
	return ErrNoNativeUI
}
