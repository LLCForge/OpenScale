//go:build linux

package peercred

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// procNetFiles are read for the socket owner; tests replace readFile.
var (
	readFile     = os.ReadFile
	procNetFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	euid         = os.Geteuid
	userGroups   = func(uid int) []string {
		u, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			return nil
		}
		gs, _ := u.GroupIds()
		return gs
	}
	lookupGroup = func(name string) (string, bool) {
		g, err := user.LookupGroup(name)
		if err != nil {
			return "", false
		}
		return g.Gid, true
	}
)

const maxProcNet = 8 << 20

// Lookup returns the owner of the client socket of the loopback
// connection client -> server, read from /proc/net/tcp{,6}: the same uid
// SO_PEERCRED would give.
func Lookup(client, server netip.AddrPort) (Identity, error) {
	for _, f := range procNetFiles {
		data, err := readFile(f)
		if err != nil || len(data) > maxProcNet {
			continue
		}
		if uid, ok := findUID(data, client, server); ok {
			id := Identity{UID: uid, Admin: uid == 0, Self: uid == euid()}
			id.Groups = userGroups(uid)
			return id, nil
		}
	}
	return Identity{}, ErrNotFound
}

// findUID scans one /proc/net/tcp file.
func findUID(data []byte, client, server netip.AddrPort) (int, bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 512), 4096)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		local, ok1 := parseProcAddr(f[1])
		remote, ok2 := parseProcAddr(f[2])
		if !ok1 || !ok2 || local != client || remote != server {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			return 0, false
		}
		return uid, true
	}
	return 0, false
}

// parseProcAddr decodes "0100007F:1F90" (IPv4) or a 32-digit IPv6 form.
// Addresses are stored as host-order 32-bit words; ports are big-endian
// hex numbers.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	// Each 32-bit word was printed as a host-order (little-endian on
	// every Linux target we build) integer.
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(out[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	a, ok := netip.AddrFromSlice(out)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true
}

// groupMember reports whether one of gids is the group's id.
func groupMember(name string, gids []string) bool {
	gid, ok := lookupGroup(name)
	if !ok {
		return false
	}
	for _, g := range gids {
		if g == gid {
			return true
		}
	}
	return false
}
