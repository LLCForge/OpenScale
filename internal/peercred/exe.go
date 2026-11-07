package peercred

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Client program identity (#645, ADR-0195 section 6). Besides the token
// and the user check of Policy, the local API can require that the
// calling process runs an OpenScale program: the same file as the server
// (its path, or a file with the same SHA-256), so only OpenScale's own
// tray, window and CLI can talk to it. A script or another program of the
// same user is refused even when it stole the token file.
//
// Limits: the program file is hashed when the request arrives, not when
// the process started; Windows keeps a running image from being written
// but not from being renamed. The check raises the bar for malware of the
// same user, it does not stop an administrator.

// ErrForeignProgram: the caller runs a program that is not OpenScale.
var ErrForeignProgram = errors.New("caller is not an OpenScale program")

// maxProgramSize bounds hashing.
const maxProgramSize = 512 << 20

// ProgramPolicy lists the allowed client programs.
type ProgramPolicy struct {
	// Paths are allowed program files (compared without case on Windows).
	Paths []string
	// Hashes are allowed SHA-256 digests of program files.
	Hashes [][32]byte
}

// SelfProgramPolicy allows the program this process runs.
func SelfProgramPolicy() (ProgramPolicy, error) {
	exe, err := os.Executable()
	if err != nil {
		return ProgramPolicy{}, err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	sum, err := HashProgram(exe)
	if err != nil {
		return ProgramPolicy{}, err
	}
	return ProgramPolicy{Paths: []string{exe}, Hashes: [][32]byte{sum}}, nil
}

// HashProgram returns the SHA-256 of a program file.
func HashProgram(path string) ([32]byte, error) {
	var sum [32]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxProgramSize+1))
	if err != nil {
		return sum, err
	}
	if n > maxProgramSize {
		return sum, errors.New("program file too large to hash")
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// AllowsProgram checks a program file path against the policy.
func (p ProgramPolicy) AllowsProgram(path string) error {
	if path == "" {
		return ErrForeignProgram
	}
	for _, a := range p.Paths {
		if samePath(a, path) {
			return nil
		}
	}
	if len(p.Hashes) == 0 {
		return fmt.Errorf("%w: %s", ErrForeignProgram, path)
	}
	sum, err := HashProgram(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrForeignProgram, path, err)
	}
	for _, h := range p.Hashes {
		if subtle.ConstantTimeCompare(h[:], sum[:]) == 1 {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrForeignProgram, path)
}

// CheckProgram finds the process behind the loopback connection and
// checks its program. Where the system cannot tell the process (Linux
// knows only the socket's user, other systems nothing), it returns nil
// and the token and user checks decide, as before.
func (p ProgramPolicy) CheckProgram(remote, local string) error {
	client, err := parseLoopback(remote)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	server, err := parseLoopback(local)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	id, err := Lookup(client, server)
	if errors.Is(err, ErrUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if id.PID <= 0 {
		return nil
	}
	path, err := ProcessImagePath(id.PID)
	if errors.Is(err, ErrUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if err := p.AllowsProgram(path); err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	return nil
}

// ProcessOf returns the process id behind a loopback connection, or 0
// when the system cannot tell.
func ProcessOf(remote, local string) (int, error) {
	client, err := parseLoopback(remote)
	if err != nil {
		return 0, err
	}
	server, err := parseLoopback(local)
	if err != nil {
		return 0, err
	}
	id, err := Lookup(client, server)
	if errors.Is(err, ErrUnsupported) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return id.PID, nil
}

// maxAncestry bounds the parent walk.
const maxAncestry = 64

// IsDescendant reports whether pid is ancestor or one of its descendants
// (#646: requests of the WebView2 window come from its browser child
// processes). A recycled process id cannot pass for the ancestor: a
// parent that started after its child is not counted.
func IsDescendant(pid, ancestor int) (bool, error) {
	if pid <= 0 || ancestor <= 0 {
		return false, nil
	}
	cur := pid
	for range maxAncestry {
		if cur == ancestor {
			return true, nil
		}
		parent, err := parentProcess(cur)
		if err != nil {
			return false, err
		}
		if parent <= 0 || parent == cur {
			return false, nil
		}
		cur = parent
	}
	return false, nil
}
