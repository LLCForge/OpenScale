//go:build !windows

package cli

import "os"

// enableVirtualTerminal is needed only on Windows consoles.
func enableVirtualTerminal(*os.File) func() { return func() {} }
