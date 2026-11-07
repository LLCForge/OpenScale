//go:build linux

package dbuswire

import (
	"net"
	"os"
	"syscall"
)

// Read reads bytes; on a Unix socket it also collects the descriptors
// sent with them. Go's ReadMsgUnix sets MSG_CMSG_CLOEXEC on Linux, so a
// received descriptor never leaks into a child process.
func (t *fdConn) Read(p []byte) (int, error) {
	uc, ok := t.Conn.(*net.UnixConn)
	if !ok {
		return t.Conn.Read(p)
	}
	oob := make([]byte, syscall.CmsgSpace(maxFDs*4))
	n, oobn, flags, _, err := uc.ReadMsgUnix(p, oob)
	if n < 0 {
		n = 0 // the system call failed; bufio refuses negative counts
	}
	if oobn > 0 {
		files, perr := parseRights(oob[:oobn])
		if perr == nil && flags&syscall.MSG_CTRUNC != 0 {
			perr = malformed("tanımlayıcı listesi kesildi")
		}
		if perr == nil {
			perr = t.push(files)
		} else {
			for _, f := range files {
				_ = f.Close()
			}
		}
		if perr != nil {
			return n, perr
		}
	}
	return n, err
}

func parseRights(oob []byte) ([]*os.File, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, malformed("denetim iletisi")
	}
	var files []*os.File
	for i := range msgs {
		fds, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "dbus-fd"))
		}
	}
	return files, nil
}

// Linux has abstract sockets and descriptor passing.
const (
	abstractSupported = true
	unixFDSupported   = true
)
