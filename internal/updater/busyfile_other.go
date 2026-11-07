//go:build !windows

package updater

import "os"

// Elsewhere an open file does not stop a rename or a remove.
func renameBusy(from, to string) error { return os.Rename(from, to) }

func removeBusy(path string) error { return os.Remove(path) }
