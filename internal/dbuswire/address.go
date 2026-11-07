package dbuswire

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// Endpoint is one usable bus address: a Unix socket path or a Linux
// abstract socket name.
type Endpoint struct {
	Path     string
	Abstract string
}

// Network address for net.Dial("unix", ...): abstract names start with
// "@" in Go.
func (e Endpoint) dialAddr() string {
	if e.Abstract != "" {
		return "@" + e.Abstract
	}
	return e.Path
}

func (e Endpoint) String() string {
	if e.Abstract != "" {
		return "unix:abstract=" + e.Abstract
	}
	return "unix:path=" + e.Path
}

// ErrNoBus: no usable session bus address.
var ErrNoBus = errors.New("dbus: oturum veriyolu bulunamadı (DBUS_SESSION_BUS_ADDRESS veya $XDG_RUNTIME_DIR/bus yok)")

// maxAddress bounds the address string.
const maxAddress = 4096

// ParseAddress returns the usable endpoints of a D-Bus address list
// ("unix:path=/run/user/1000/bus;unix:abstract=/tmp/dbus-x,guid=..."),
// in order. Other transports are skipped; an address without a usable
// endpoint is an error.
func ParseAddress(addr string) ([]Endpoint, error) {
	if len(addr) > maxAddress {
		return nil, fmt.Errorf("dbus: adres çok uzun")
	}
	var out []Endpoint
	for _, entry := range strings.Split(addr, ";") {
		if entry == "" {
			continue
		}
		transport, params, ok := strings.Cut(entry, ":")
		if !ok || transport != "unix" {
			continue
		}
		kv := map[string]string{}
		bad := false
		for _, p := range strings.Split(params, ",") {
			if p == "" {
				continue
			}
			k, v, ok := strings.Cut(p, "=")
			if !ok || k == "" {
				bad = true
				break
			}
			dv, err := unescapeAddress(v)
			if err != nil {
				bad = true
				break
			}
			if _, dup := kv[k]; dup {
				bad = true
				break
			}
			kv[k] = dv
		}
		if bad {
			continue
		}
		path, abstract := kv["path"], kv["abstract"]
		switch {
		case path != "" && abstract == "":
			if !strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
				continue
			}
			out = append(out, Endpoint{Path: path})
		case abstract != "" && path == "":
			if strings.ContainsRune(abstract, 0) {
				continue
			}
			out = append(out, Endpoint{Abstract: abstract})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: desteklenen bir unix adresi yok", ErrNoBus)
	}
	return out, nil
}

// unescapeAddress decodes the address value escaping ("%2f").
func unescapeAddress(v string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(v) {
			return "", errors.New("eksik kaçış")
		}
		hi, ok1 := unhex(v[i+1])
		lo, ok2 := unhex(v[i+2])
		if !ok1 || !ok2 {
			return "", errors.New("geçersiz kaçış")
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// SessionEndpoints returns where the session bus is: the
// DBUS_SESSION_BUS_ADDRESS list, else $XDG_RUNTIME_DIR/bus.
func SessionEndpoints() ([]Endpoint, error) {
	return sessionEndpoints(os.Getenv)
}

func sessionEndpoints(getenv func(string) string) ([]Endpoint, error) {
	if a := getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" {
		return ParseAddress(a)
	}
	if dir := getenv("XDG_RUNTIME_DIR"); strings.HasPrefix(dir, "/") {
		return []Endpoint{{Path: path.Join(dir, "bus")}}, nil
	}
	return nil, ErrNoBus
}
