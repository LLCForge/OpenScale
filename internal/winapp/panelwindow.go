package winapp

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/webview"
)

// Panel in a native window (ADR-0170, ADR-0195). The tray and the
// "openscale window" command show the panel with internal/webview; when
// no window can be shown (no WebView2 runtime, a build without cgo on
// macOS or Linux, no graphical session) they fall back to the browser
// path that existed before: the isolated Edge/Chrome app window on
// Windows (#520) and the system browser elsewhere.

// TicketPath is the panel's one-time sign-in address; an open window
// accepts a fresh one from the tray instead of a second window opening.
const TicketPath = "/auth/ticket"

// PanelWindowEnv set to "browser" skips the native window.
const PanelWindowEnv = "OPENSCALE_PANEL_WINDOW"

// Exit codes of "openscale panel-window", read by the tray.
const (
	PanelWindowExitClosed      = 0
	PanelWindowExitUnavailable = 3
	PanelWindowExitInvalid     = 2
)

// ErrWindowUnavailable: no native window; use the browser.
var ErrWindowUnavailable = webview.ErrUnavailable

// NativeWindowDisabled reports whether the owner turned the window off.
func NativeWindowDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(PanelWindowEnv)), "browser")
}

// PanelWindowOptions are the window settings of the panel.
func PanelWindowOptions(link, title string) (webview.Options, error) {
	u, err := validateLoopbackURL(link)
	if err != nil {
		return webview.Options{}, err
	}
	return webview.Options{
		URL:     u,
		Title:   windowTitle(title),
		IconPNG: appIconPNG,
		IconICO: appIconICO,
		// Single window (W2): the tray hands a new ticket to the open one.
		ForwardPath: TicketPath,
	}, nil
}

// OpenPanelWindow shows the panel in a native window and blocks until it
// is closed. An error matching ErrWindowUnavailable means the caller
// should use the browser. On macOS it must run on the main goroutine.
func OpenPanelWindow(ctx context.Context, link, title string) error {
	if NativeWindowDisabled() {
		return ErrWindowUnavailable
	}
	opts, err := PanelWindowOptions(link, title)
	if err != nil {
		return err
	}
	if ForwardToPanelWindow(link) == nil {
		// Another window is open: it loads the link and comes to the front.
		return nil
	}
	return webview.Open(ctx, opts)
}

// ForwardToPanelWindow hands a one-time sign-in link to the open panel
// window and brings it to the front (Windows). It fails when no window is
// open, the open one is not verifiably this program's (panelwindow_verify)
// or the window refuses the link; then a new window is needed.
func ForwardToPanelWindow(link string) error {
	if _, err := validateLoopbackURL(link); err != nil {
		return err
	}
	return webview.ForwardToOpenWindow(link, verifyPanelWindowProcess)
}

// windowTitle is title when it is a valid neutral name, else the
// process's DisplayName. The tray passes its own DisplayName, because the
// non-elevated window process cannot read the administrator-only
// setting (ADR-0196).
func windowTitle(title string) string {
	if title == "OpenScale" || (title != "" && ValidNeutralName(title) == nil) {
		return title
	}
	return DisplayName()
}

// isOpenScaleProgram reports whether exe is the OpenScale program by its
// file name (openscale or openscale.exe, any case).
func isOpenScaleProgram(exe string) bool {
	name := strings.ToLower(filepath.Base(exe))
	return name == "openscale.exe" || name == "openscale"
}
