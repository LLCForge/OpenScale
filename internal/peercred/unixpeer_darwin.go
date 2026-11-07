//go:build darwin

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
// socket (ADR-0227): LOCAL_PEERCRED gives the effective user and groups
// the peer had when it connected, LOCAL_PEERPID its process id. Unlike a
// loopback TCP port nothing here can be spoofed by the peer. Admin is
// root; the caller decides about groups (Identity.Groups holds the
// numeric group ids).
func UnixPeer(c *net.UnixConn) (Identity, error) {
	id := Identity{UID: -1}
	raw, err := c.SyscallConn()
	if err != nil {
		return id, err
	}
	var (
		cred  *unix.Xucred
		pid   int
		opErr error
	)
	ctlErr := raw.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if opErr != nil {
			return
		}
		pid, opErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if ctlErr != nil {
		return id, ctlErr
	}
	if opErr != nil {
		return id, fmt.Errorf("peer credentials: %w", opErr)
	}
	return identityFromXucred(cred, pid, os.Geteuid())
}

// xucredVersion is XUCRED_VERSION of <sys/ucred.h>.
const xucredVersion = 0

func identityFromXucred(cred *unix.Xucred, pid, selfUID int) (Identity, error) {
	id := Identity{UID: -1}
	if cred == nil || cred.Version != xucredVersion {
		return id, errors.New("peer credentials: unexpected structure version")
	}
	if cred.Ngroups < 0 || int(cred.Ngroups) > len(cred.Groups) {
		return id, errors.New("peer credentials: invalid group count")
	}
	if pid <= 0 {
		return id, errors.New("peer credentials: no process id")
	}
	id.PID = pid
	id.UID = int(cred.Uid)
	id.Admin = cred.Uid == 0
	id.Self = id.UID == selfUID
	for _, g := range cred.Groups[:cred.Ngroups] {
		id.Groups = append(id.Groups, strconv.FormatUint(uint64(g), 10))
	}
	return id, nil
}
