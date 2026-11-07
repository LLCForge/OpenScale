//go:build linux

package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// UnixPeer asks the kernel who is at the other end of a Unix domain
// socket (ADR-0234): SO_PEERCRED gives the process id, user and primary
// group the peer had when it connected. Unlike a loopback TCP port
// nothing here can be spoofed by the peer. Supplementary groups are not
// part of SO_PEERCRED: Groups holds the primary group only and the caller
// asks the group database for more (the tray gateway does).
func UnixPeer(c *net.UnixConn) (Identity, error) {
	id := Identity{UID: -1}
	raw, err := c.SyscallConn()
	if err != nil {
		return id, err
	}
	var (
		cred  *unix.Ucred
		opErr error
	)
	ctlErr := raw.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctlErr != nil {
		return id, ctlErr
	}
	if opErr != nil {
		return id, fmt.Errorf("peer credentials: %w", opErr)
	}
	return identityFromUcred(cred, os.Geteuid())
}

func identityFromUcred(cred *unix.Ucred, selfUID int) (Identity, error) {
	id := Identity{UID: -1}
	if cred == nil {
		return id, errors.New("peer credentials: missing")
	}
	if cred.Pid <= 0 {
		return id, errors.New("peer credentials: no process id")
	}
	id.PID = int(cred.Pid)
	id.UID = int(cred.Uid)
	id.Admin = cred.Uid == 0
	id.Self = id.UID == selfUID
	id.Groups = []string{strconv.FormatUint(uint64(cred.Gid), 10)}
	return id, nil
}
