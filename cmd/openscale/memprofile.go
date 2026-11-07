package main

import (
	"fmt"
	"os"

	"github.com/openscale/openscale/internal/memprofile"
)

// applyMemoryProfile applies OPENSCALE_MEMORY_PROFILE (#392) before any
// command runs: the Windows service, "up", the coordinator and the tools
// all run in this one program. A wrong name keeps the default profile.
func applyMemoryProfile() {
	if _, err := memprofile.ApplyFromEnv(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "UYARI:", err)
	}
}
