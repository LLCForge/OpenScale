//go:build !windows

package cli

import (
	"context"

	"github.com/openscale/openscale/internal/rdesk"
)

// desktopConsent: there is no dialog without cgo on X11, so attended
// sessions are refused (fail closed); only rules with allow_unattended
// open a session, and the indicator goes to the terminal and the log.
func desktopConsent(context.Context, rdesk.ConsentRequest) bool { return false }

func desktopIndicator(rdesk.SessionEvent) {}

func desktopPromptsAvailable() bool { return false }
