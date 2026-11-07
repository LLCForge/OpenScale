//go:build unix && !linux

package sshd

// startPTY is not implemented on this platform; sessions fall back to
// running without a terminal.
func startPTY(procRequest, ptyParams) (process, ptyTerminal, error) {
	return nil, nil, errNoPTY
}
