// Package geoip maps a public IP address to the country its block is
// registered in. The table is built from the public RIR delegation files
// (tools/geoipgen) and embedded, so lookups never leave the computer. It is
// country level only and reflects registration, not physical location.
package geoip

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

//go:embed data.bin.gz
var compressed []byte

const (
	magic      = "OSGEO1"
	maxDataLen = 32 << 20
)

type table struct {
	date   string
	v4     []uint32
	v4cc   []string
	v6     []uint64
	v6cc   []string
	loaded bool
}

var (
	once sync.Once
	tab  table
)

func load() {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(zr, maxDataLen))
	if err != nil {
		return
	}
	t, err := decode(data)
	if err != nil {
		return
	}
	tab = t
}

func decode(data []byte) (table, error) {
	var t table
	if len(data) < len(magic)+8 || string(data[:len(magic)]) != magic {
		return t, errors.New("bad geoip data")
	}
	t.date = strings.TrimSpace(string(data[len(magic) : len(magic)+8]))
	rest := data[len(magic)+8:]
	read := func(width int) ([]uint64, []string, error) {
		if len(rest) < 4 {
			return nil, nil, errors.New("truncated geoip data")
		}
		n := int(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if n < 0 || n*(width+2) > len(rest) {
			return nil, nil, errors.New("truncated geoip data")
		}
		starts, ccs := make([]uint64, n), make([]string, n)
		for i := 0; i < n; i++ {
			if width == 4 {
				starts[i] = uint64(binary.BigEndian.Uint32(rest))
			} else {
				starts[i] = binary.BigEndian.Uint64(rest)
			}
			ccs[i] = string(rest[width : width+2])
			rest = rest[width+2:]
		}
		return starts, ccs, nil
	}
	s4, c4, err := read(4)
	if err != nil {
		return t, err
	}
	s6, c6, err := read(8)
	if err != nil {
		return t, err
	}
	t.v4 = make([]uint32, len(s4))
	for i, v := range s4 {
		t.v4[i] = uint32(v)
	}
	t.v4cc, t.v6, t.v6cc, t.loaded = c4, s6, c6, true
	return t, nil
}

// Country returns the ISO 3166-1 alpha-2 code ("TR") for a public address,
// or "" for private, special or unknown addresses.
func Country(a netip.Addr) string {
	once.Do(load)
	a = a.Unmap()
	if !tab.loaded || !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return ""
	}
	var cc string
	if a.Is4() {
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		i := sort.Search(len(tab.v4), func(i int) bool { return tab.v4[i] > v }) - 1
		if i >= 0 {
			cc = tab.v4cc[i]
		}
	} else {
		b := a.As16()
		v := binary.BigEndian.Uint64(b[:8])
		i := sort.Search(len(tab.v6), func(i int) bool { return tab.v6[i] > v }) - 1
		if i >= 0 {
			cc = tab.v6cc[i]
		}
	}
	if cc == "--" {
		return ""
	}
	return cc
}

// DataDate is the date of the RIR files the table was built from.
func DataDate() string {
	once.Do(load)
	return tab.date
}
