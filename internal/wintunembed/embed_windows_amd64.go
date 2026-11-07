//go:build windows && amd64

package wintunembed

import _ "embed"

// SHA-256 e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
//
//go:embed dll/amd64/wintun.dll
var embedded []byte
