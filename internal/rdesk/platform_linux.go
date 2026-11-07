//go:build linux

package rdesk

import (
	"context"
	"fmt"
	"os"
	"time"
)

// NewScreenCapturer opens the screen of the user's graphical session,
// chosen by XDG_SESSION_TYPE: on Wayland a ScreenCast portal session
// (the user agrees in the portal's dialog; ADR-0236), otherwise the X11
// display named by DISPLAY (with the cookie from XAUTHORITY or
// ~/.Xauthority). The process must run in, or be given the environment
// of, that session.
func NewScreenCapturer() (Capturer, error) {
	if WaylandSession() {
		ctx, cancel := context.WithTimeout(context.Background(), portalUserTimeout+30*time.Second)
		defer cancel()
		s, err := openPortalSession(ctx, false)
		if err != nil {
			return nil, err
		}
		return &waylandCapturer{s: s}, nil
	}
	x, err := dialX11(os.Getenv("DISPLAY"), os.Getenv("XAUTHORITY"))
	if err != nil {
		return nil, err
	}
	return &x11Capturer{x: x}, nil
}

// NewInputInjector opens the X11 display and the XTEST extension. On
// Wayland input belongs to the portal session of the screen and is opened
// with it (platformDevices); on its own it is refused.
func NewInputInjector() (Injector, error) {
	if WaylandSession() {
		return nil, fmt.Errorf("%w: Wayland'da girdi ekran paylaşımı oturumuyla birlikte açılır", ErrUnsupported)
	}
	x, err := dialX11(os.Getenv("DISPLAY"), os.Getenv("XAUTHORITY"))
	if err != nil {
		return nil, err
	}
	in, err := newX11Injector(x)
	if err != nil {
		_ = x.Close()
		return nil, err
	}
	return in, nil
}

// NewSystemClipboard is not implemented on Linux: X11 selections need an
// event-driven owner window and Wayland has no clipboard for background
// programs; control sessions run without clipboard sharing.
func NewSystemClipboard() (Clipboard, error) { return nil, ErrUnsupported }
