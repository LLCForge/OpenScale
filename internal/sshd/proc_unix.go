//go:build unix

package sshd

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	unixShell    = "/bin/sh"
	userPath     = "/usr/local/bin:/usr/bin:/bin"
	rootPath     = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	fallbackHome = "/"
)

// buildCommand prepares the shell invocation with a minimal environment;
// the server's own environment is never inherited.
func buildCommand(req procRequest, withPTY bool) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	if req.command == "" {
		cmd = exec.Command(unixShell, "-l")
	} else {
		cmd = exec.Command(unixShell, "-c", req.command)
	}
	home := req.acct.home
	if fi, err := os.Stat(home); home == "" || err != nil || !fi.IsDir() {
		home = fallbackHome
	}
	path := userPath
	if req.acct.uid == 0 {
		path = rootPath
	}
	cmd.Dir = home
	cmd.Env = append([]string{
		"HOME=" + home,
		"USER=" + req.acct.name,
		"LOGNAME=" + req.acct.name,
		"SHELL=" + unixShell,
		"PATH=" + path,
	}, req.env...)
	attr := &syscall.SysProcAttr{}
	if !withPTY {
		// A separate process group lets kill() reach every descendant.
		attr.Setpgid = true
	}
	if req.acct.switchUser {
		attr.Credential = &syscall.Credential{Uid: req.acct.uid, Gid: req.acct.gid, Groups: req.acct.groups}
	}
	cmd.SysProcAttr = attr
	return cmd, nil
}

// afterStart returns functions that kill the process group and clean up.
func afterStart(cmd *exec.Cmd) (kill func(), onExit func()) {
	pid := cmd.Process.Pid
	return func() { _ = syscall.Kill(-pid, syscall.SIGKILL) }, nil
}
