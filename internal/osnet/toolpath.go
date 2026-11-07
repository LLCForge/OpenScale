package osnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// System tools by absolute path (F-125, #297). The service runs as SYSTEM
// or root; finding netsh, ip or nft through PATH would let whoever
// controls PATH (an installer, a user's shell profile, a writable folder
// early in PATH) choose what runs with those rights. Tools are therefore
// looked up only in the system folders, and run with a fixed, minimal
// environment on Unix.

// errToolNotFound is wrapped with the tool name.
var errToolNotFound = errors.New("sistem aracı bulunamadı")

// IsToolNotFound reports whether err says a system tool is not installed.
func IsToolNotFound(err error) bool { return errors.Is(err, errToolNotFound) }

// lookTool returns the absolute path of a system tool.
func lookTool(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: geçersiz ad %q", errToolNotFound, name)
	}
	for _, dir := range toolDirs() {
		for _, file := range toolFileNames(name) {
			p := filepath.Join(dir, file)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && executableMode(fi.Mode()) {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s (%s)", errToolNotFound, name, strings.Join(toolDirs(), ", "))
}

// toolCommand is exec.CommandContext for a system tool by absolute path,
// with the environment toolEnv gives.
func toolCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	p, err := lookTool(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = toolEnv()
	return cmd, nil
}
