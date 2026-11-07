//go:build windows && arm

package wintunembed

import _ "embed"

// SHA-256 daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9
//
//go:embed dll/arm/wintun.dll
var embedded []byte
