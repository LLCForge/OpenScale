//go:build windows && 386

package wintunembed

import _ "embed"

// SHA-256 d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931
//
//go:embed dll/x86/wintun.dll
var embedded []byte
