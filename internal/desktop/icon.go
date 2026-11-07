package desktop

import _ "embed"

// tray.png is logos/favicon-64x64.png: the simplified mark on the dark
// rounded square, readable on both light and dark taskbars.
//
//go:embed assets/tray.png
var trayIcon []byte

func init() { trayIconPNG = trayIcon }
