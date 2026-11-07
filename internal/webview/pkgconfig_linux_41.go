//go:build linux && cgo && !nowebview && !webkit2gtk_40

package webview

// WebKitGTK 4.1 (libsoup 3) is the default; build with the webkit2gtk_40
// tag on systems that only have 4.0.

// #cgo pkg-config: gtk+-3.0 webkit2gtk-4.1
import "C"
