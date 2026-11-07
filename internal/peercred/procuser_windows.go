//go:build windows

package peercred

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// ProcessUser returns the account (SID) a process runs as.
func ProcessUser(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", fmt.Errorf("open token of process %d: %w", pid, err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("user of process %d: %w", pid, err)
	}
	return u.User.Sid.String(), nil
}
