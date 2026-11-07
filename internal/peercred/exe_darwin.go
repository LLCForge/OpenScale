//go:build darwin

package peercred

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// maxProcArgs bounds what kern.procargs2 may return (ARG_MAX is 1 MiB).
const maxProcArgs = 1 << 20

// ProcessImagePath returns the program file of a process from
// kern.procargs2: a 4-byte argument count followed by the path the
// process was started with. Only an absolute path is returned; a relative
// one cannot be resolved safely after the fact.
func ProcessImagePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("image of process %d: invalid process id", pid)
	}
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return "", fmt.Errorf("image of process %d: %w", pid, ErrNotFound)
		}
		return "", fmt.Errorf("image of process %d: %w", pid, err)
	}
	return parseProcArgs(buf)
}

// parseProcArgs reads the executable path out of a kern.procargs2 reply.
func parseProcArgs(buf []byte) (string, error) {
	if len(buf) < 5 || len(buf) > maxProcArgs {
		return "", errors.New("kern.procargs2: unexpected size")
	}
	if argc := int32(binary.LittleEndian.Uint32(buf[:4])); argc < 0 {
		return "", errors.New("kern.procargs2: negative argument count")
	}
	rest := buf[4:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 {
		return "", errors.New("kern.procargs2: no executable path")
	}
	p := string(rest[:end])
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("kern.procargs2: relative executable path %q", p)
	}
	return filepath.Clean(p), nil
}

// parentProcess reads the parent process id from kern.proc.pid.
func parentProcess(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if int(kp.Proc.P_pid) != pid {
		return 0, ErrNotFound
	}
	return int(kp.Eproc.Ppid), nil
}
