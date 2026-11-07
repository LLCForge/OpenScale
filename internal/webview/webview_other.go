//go:build !windows && !(((darwin && cgo) || (linux && cgo)) && !nowebview)

package webview

import "context"

// open: this build has no native window binding (another system, macOS or
// Linux built without cgo, or the nowebview build tag). The caller falls
// back to the browser.
func open(context.Context, config) error { return ErrUnsupported }
