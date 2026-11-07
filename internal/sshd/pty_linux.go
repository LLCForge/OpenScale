//go:build linux

package sshd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxPTY struct {
	master *os.File
}

func (t *linuxPTY) Read(p []byte) (int, error) {
	n, err := t.master.Read(p)
	// After the last slave descriptor closes, Linux reports EIO.
	if err != nil && errors.Is(err, syscall.EIO) {
		return n, errEOF
	}
	return n, err
}

func (t *linuxPTY) Write(p []byte) (int, error) { return t.master.Write(p) }
func (t *linuxPTY) ProcessExited()              {}
func (t *linuxPTY) Close() error                { return t.master.Close() }

type ptyProcess struct {
	*cmdProcess
	master *os.File
}

func (p *ptyProcess) resize(cols, rows uint32) { setWinsize(p.master, cols, rows) }

func setWinsize(f *os.File, cols, rows uint32) {
	rc, err := f.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)})
	})
}

// openPTY opens a new pseudo terminal pair through /dev/ptmx.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = master.Close()
		}
	}()
	rc, err := master.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var n uint32
	var ioctlErr error
	if err = rc.Control(func(fd uintptr) {
		if ioctlErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); ioctlErr != nil {
			return
		}
		n, ioctlErr = unix.IoctlGetUint32(int(fd), unix.TIOCGPTN)
	}); err != nil {
		return nil, nil, err
	}
	if ioctlErr != nil {
		return nil, nil, ioctlErr
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return master, slave, nil
}

// startPTY starts req attached to a new pseudo terminal as session leader
// with the terminal as its controlling tty.
func startPTY(req procRequest, params ptyParams) (process, ptyTerminal, error) {
	master, slave, err := openPTY()
	if err != nil {
		return nil, nil, fmt.Errorf("PTY açılamadı: %w", err)
	}
	defer slave.Close()
	setWinsize(master, params.cols, params.rows)
	if req.acct.switchUser {
		// The session's user must own its terminal.
		_ = slave.Chown(int(req.acct.uid), -1)
	}
	cmd, err := buildCommand(req, true)
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}
	cmd.Env = append(cmd.Env, "TERM="+sanitizeTerm(params.term))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Ctty = 0
	if err := cmd.Start(); err != nil {
		_ = master.Close()
		return nil, nil, err
	}
	p := &cmdProcess{cmd: cmd}
	p.killFn, p.onExit = afterStart(cmd)
	return &ptyProcess{cmdProcess: p, master: master}, &linuxPTY{master: master}, nil
}
