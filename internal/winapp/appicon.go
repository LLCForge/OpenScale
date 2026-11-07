package winapp

import _ "embed"

// The panel window's icon from the logo pack (logos/app-icon.ico and
// logos/app-icon-256.png), the same mark the panel and the program file
// show. The .ico carries the simplified small sizes for the title bar.

//go:embed assets/app-icon.ico
var appIconICO []byte

//go:embed assets/app-icon-256.png
var appIconPNG []byte
