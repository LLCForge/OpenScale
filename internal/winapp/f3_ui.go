package winapp

import "errors"

// Small native windows of the tray (#802 status flyout, #813 file offer,
// #803 recipient picker). They are read-only views with a few buttons:
// nothing in them signs or changes the network. The description of what
// to show is a UIModel; the Windows implementation paints it with GDI in
// the light or dark colors of the system (f3_window_windows.go). Other
// systems have no tray of this kind.

// Line styles.
const (
	LineBody = iota
	LineTitle
	LineMuted
	LineWarn
	LineHeading
)

// UILine is one row of text; Value, when set, is shown on the right.
type UILine struct {
	Text  string
	Value string
	Style int
}

// UIButton is a button; ID is returned when it is pressed.
type UIButton struct {
	ID      int
	Label   string
	Primary bool
}

// UIModel is what a window shows.
type UIModel struct {
	// Title is the window caption (dialogs) and its accessible name.
	Title string
	Lines []UILine
	// List is a selectable list (the recipient picker); Selected is the
	// highlighted row, -1 for none.
	List     []string
	Selected int
	// Progress is 0..1 for a progress bar, below 0 for none.
	Progress float64
	Buttons  []UIButton
}

// UIResult is how a window was closed: the pressed button's ID (0 when
// it was dismissed) and the list row selected at that moment.
type UIResult struct {
	Button   int
	Selected int
}

// UIKind chooses the window's behaviour.
type UIKind int

const (
	// UIFlyout appears next to the notification area, has no caption and
	// closes when it loses the focus.
	UIFlyout UIKind = iota
	// UIDialog is a small captioned window in the middle of the screen.
	UIDialog
)

// ErrNoNativeUI is returned where these windows do not exist.
var ErrNoNativeUI = errors.New("bu sistemde yerel pencere yok")

// FlyoutOpenPanel is the ID of the flyout's "Open panel" button.
const FlyoutOpenPanel = 1

// Left click choices of the Windows tray (#802).
const (
	LeftClickFlyout = "flyout"
	LeftClickPanel  = "panel"
)

var errUnknownLeftClick = errors.New("sol tık seçimi flyout veya panel olmalı")

// Tr returns the Turkish or the English text for the display language.
func Tr(tr, en string) string {
	if UITurkish() {
		return tr
	}
	return en
}
