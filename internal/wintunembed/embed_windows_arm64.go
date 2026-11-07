//go:build windows && arm64

package wintunembed

import _ "embed"

// SHA-256 f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80
//
//go:embed dll/arm64/wintun.dll
var embedded []byte
