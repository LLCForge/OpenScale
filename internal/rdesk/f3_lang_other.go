//go:build !windows

package rdesk

import (
	"os"
	"strings"
)

// uiTurkish reports whether the session's language is Turkish (LC_ALL,
// LC_MESSAGES or LANG starts with "tr"); without any it stays Turkish like
// the rest of the program.
func uiTurkish() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			return strings.HasPrefix(strings.ToLower(v), "tr")
		}
	}
	return true
}
