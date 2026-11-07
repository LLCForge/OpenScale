package webview

import (
	"errors"
	"net/url"
	"strings"
)

// Forwarding a sign-in address to the open window (single window, W2).
// A second "open the panel" (tray item, second launch) does not create
// another window: it finds the open one, hands it a fresh address and
// brings it to the front. The window loads the address only when it is
// inside its allowed origin and its path is exactly the configured
// forward path; every load still passes the NavigationStarting checks.

// maxForwardPath bounds Options.ForwardPath.
const maxForwardPath = 128

// copyDataForward tags the forward message ("OSFW").
const copyDataForward = 0x4F534657

// ErrNoOpenWindow: no window to forward to.
var ErrNoOpenWindow = errors.New("webview: açık pencere yok")

// TargetCheck decides whether the process that owns a window may receive
// a forwarded address (a sign-in ticket); nil error allows it.
type TargetCheck func(pid uint32) error

func validForwardPath(p string) error {
	if len(p) > maxForwardPath || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\\ \t\r\n") || strings.Contains(p, "..") {
		return errors.New("webview: ForwardPath geçersiz")
	}
	return nil
}

// acceptForward reports whether the window with cfg may load u on
// another program's request.
func (c *config) acceptForward(u string) bool {
	if c.forwardPath == "" || len(u) > maxURLBytes || c.origin.check(u) != actionAllow {
		return false
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Fragment != "" || parsed.User != nil {
		return false
	}
	return parsed.Path == c.forwardPath
}

// errForwardRefused: the open window refused the address.
var errForwardRefused = errors.New("webview: açık pencere adresi kabul etmedi")
