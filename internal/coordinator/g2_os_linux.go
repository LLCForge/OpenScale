//go:build linux

package coordinator

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// RAM file system magic numbers (statfs f_type).
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// stateFileSystem names the file system holding dir and reports whether it
// keeps data in memory only.
func stateFileSystem(dir string) (string, bool, error) {
	if dir == "" {
		return "", false, fmt.Errorf("no state directory")
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", false, err
	}
	// The magic is 32 bits wide; f_type is int32 on some 32-bit systems.
	switch uint32(st.Type) { //nolint:gosec // truncation intended
	case tmpfsMagic:
		return "tmpfs", true, nil
	case ramfsMagic:
		return "ramfs", true, nil
	}
	return fmt.Sprintf("0x%x", uint32(st.Type)), false, nil //nolint:gosec // display only
}

// swapActive reports whether any swap area is in use (/proc/swaps has more
// than its header line).
func swapActive() bool {
	f, err := os.Open("/proc/swaps")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n > 1
}

// ensureNoCoreDumps clears the dumpable flag and the core size limit again
// (cmd/openscale does it at start, internal/privacy) and reports the state.
func ensureNoCoreDumps() string {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	var r unix.Rlimit
	limOK := unix.Getrlimit(unix.RLIMIT_CORE, &r) == nil && r.Cur == 0
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	switch {
	case err == nil && d == 0 && limOK:
		return "off"
	case err == nil && d == 0 || limOK:
		return "partial"
	}
	return "on"
}
