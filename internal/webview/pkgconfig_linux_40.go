//go:build linux && cgo && !nowebview && webkit2gtk_40

package webview

// WebKitGTK 4.0 (libsoup 2) for older distributions.

// #cgo pkg-config: gtk+-3.0 webkit2gtk-4.0
import "C"
