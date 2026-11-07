// Package wintunembed ships the signed Wintun driver DLL inside the
// openscale binary on Windows, so `openscale up` works from a single file.
//
// wireguard-go loads wintun.dll by name from the application directory or
// System32. Before the tunnel starts, Ensure verifies the DLL next to the
// executable against the SHA-256 of the embedded copy (rewriting it if it
// is missing or different), keeps the file locked against writes while it
// loads it by full path, and so pins the verified module in the process.
// A later load by name returns that same module, so a swapped DLL is never
// executed with the administrator rights `up` runs with.
//
// The DLLs are the unmodified binaries from wintun.net (Wintun 0.14.1),
// redistributed under dll/LICENSE.txt alongside software that uses them only
// through the Wintun API.
package wintunembed

import "errors"

// ErrUnsupported is returned on Windows architectures without an embedded DLL.
var ErrUnsupported = errors.New("no embedded wintun.dll for this architecture")
