//go:build linux

package sysinfo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// procTCPFiles list the TCP sockets of this network namespace.
var procTCPFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// maxProcTCP bounds one table read.
const maxProcTCP = 8 << 20

// tcpListenState is TCP_LISTEN in /proc/net/tcp.
const tcpListenState = "0A"

func listeningSockets() []listenEntry {
	var out []listenEntry
	for _, name := range procTCPFiles {
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxProcTCP))
		_ = f.Close()
		if err != nil {
			continue
		}
		out = append(out, parseProcListen(data)...)
	}
	return out
}

// parseProcListen returns the listening sockets of one /proc/net/tcp file.
func parseProcListen(data []byte) []listenEntry {
	var out []listenEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != tcpListenState {
			continue
		}
		if ap, ok := parseProcAddrPort(fields[1]); ok {
			out = append(out, listenEntry{addr: ap.Addr(), port: ap.Port()})
		}
	}
	return out
}

// parseProcAddrPort decodes "0100007F:1F90" or the 32-digit IPv6 form.
// Each 32-bit word of the address is printed in host order (little-endian
// on every Linux target we build); the port is a big-endian hex number.
func parseProcAddrPort(s string) (netip.AddrPort, bool) {
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
