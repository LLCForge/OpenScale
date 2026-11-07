//go:build linux

package surface

import (
	"io"
	"os"
	"path/filepath"
)

const (
	maxProcNet = 8 << 20
	maxFDs     = 1 << 16
)

func readLimited(name string) ([]byte, bool) {
	f, err := os.Open(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcNet))
	return data, err == nil
}

// ownInodes returns the socket inodes of this process.
func ownInodes() (map[uint64]bool, bool) {
	dir := "/proc/self/fd"
	d, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer d.Close()
	names, err := d.Readdirnames(maxFDs)
	if err != nil && len(names) == 0 {
		return nil, false
	}
	own := map[uint64]bool{}
	for _, n := range names {
		link, err := os.Readlink(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if inode, ok := SocketInode(link); ok {
			own[inode] = true
		}
	}
	return own, true
}

func own() ([]Socket, bool) {
	inodes, ok := ownInodes()
	if !ok {
		return nil, false
	}
	var out []Socket
	read := false
	for _, t := range []struct{ proto, file string }{
		{"tcp", "/proc/self/net/tcp"}, {"tcp", "/proc/self/net/tcp6"},
		{"udp", "/proc/self/net/udp"}, {"udp", "/proc/self/net/udp6"},
	} {
		data, ok := readLimited(t.file)
		if !ok {
			continue
		}
		read = true
		out = append(out, FilterProc(t.proto, ParseProcNet(data), inodes)...)
	}
	return out, read
}
