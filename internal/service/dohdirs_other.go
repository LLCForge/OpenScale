//go:build !windows

package service

import "github.com/openscale/openscale/internal/dohcheck"

// consoleUserDirs returns the folders of the user running this process.
func consoleUserDirs() dohcheck.Dirs { return dohcheck.DefaultDirs() }
