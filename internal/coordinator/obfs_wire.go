package coordinator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Starting the transport disguise (ADR-0186) from the coordinator's state
// directory. Both "openscale coordinator run" and the desktop service read
// the same file, so the setting survives restarts and is the same on both
// paths. A missing file means "off": older installations are unchanged.

// ObfsFileName is the coordinator's disguise settings file.
const ObfsFileName = "obfs-coordinator.json"

const (
	maxObfsFile  = 4 << 10
	maxObfsNames = 8
	maxObfsName  = 253
)

// ObfsFile is the saved coordinator disguise setting.
type ObfsFile struct {
	// Mode is "off" or "auto". The coordinator never forces the disguise:
	// in auto it answers each device in the form it was spoken to.
	Mode string `json:"mode"`
	// TLSListen is the TLS camouflage listener, e.g. ":443"; empty is off.
	// It needs the plain TCP transport (TCPListen) as well.
	TLSListen string `json:"tls_listen,omitempty"`
	// Names go into a newly generated certificate.
	Names []string `json:"names,omitempty"`
}

// Validate checks the file strictly.
func (f ObfsFile) Validate() error {
	switch f.Mode {
	case "", "off", "auto":
	default:
		return errors.New("gizleme kipi off veya auto olmalı (koordinatör on kipini kullanmaz)")
	}
	if f.TLSListen != "" {
		host, port, err := net.SplitHostPort(f.TLSListen)
		if err != nil {
			return fmt.Errorf("TLS gizleme adresi geçersiz: %w", err)
		}
		if host != "" && net.ParseIP(host) == nil {
			return errors.New("TLS gizleme adresinde yalnızca IP kullanılabilir")
		}
		p, err := strconv.Atoi(port)
		// Port 0 (any free port) only on loopback, for tests.
		loopback := host != "" && net.ParseIP(host).IsLoopback()
		if err != nil || p < 0 || p > 65535 || (p == 0 && !loopback) {
			return errors.New("TLS gizleme portu 1 ile 65535 arasında olmalı")
		}
	}
	if len(f.Names) > maxObfsNames {
		return fmt.Errorf("en çok %d sertifika adı", maxObfsNames)
	}
	for _, n := range f.Names {
		if n == "" || len(n) > maxObfsName || strings.ContainsAny(n, " \t\r\n/\\") {
			return fmt.Errorf("geçersiz sertifika adı: %q", n)
		}
	}
	return nil
}

// Enabled reports whether anything is turned on.
func (f ObfsFile) Enabled() bool { return f.Mode == "auto" || f.TLSListen != "" }

// LoadObfsFile reads dir's settings; a missing file is the zero value.
func LoadObfsFile(dir string) (ObfsFile, error) {
	var f ObfsFile
	data, err := securefile.ReadLimited(filepath.Join(dir, ObfsFileName), maxObfsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return ObfsFile{}, errors.New("koordinatör gizleme ayar dosyası bozuk")
	}
	if err := f.Validate(); err != nil {
		return ObfsFile{}, err
	}
	return f, nil
}

// SaveObfsFile validates and writes f to dir.
func SaveObfsFile(dir string, f ObfsFile) error {
	if err := f.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, ObfsFileName), data)
}

// ObfsRuntime is the started disguise of one coordinator run.
type ObfsRuntime struct {
	Bind *obfs.Bind
	Pin  obfs.Pin
	ln   net.Listener
	tls  *tls.Config
}

// ApplyObfs installs the disguise into cfg (cfg.Bind) and opens the TLS
// listener. dir holds the certificate. Call Serve after New succeeded and
// Close when New failed. A nil runtime with nil error means "off".
func ApplyObfs(cfg *Config, dir string, f ObfsFile, now time.Time) (*ObfsRuntime, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	if !f.Enabled() {
		return nil, nil
	}
	if cfg.Store == nil {
		return nil, errors.New("koordinatör belgesi yok")
	}
	doc := cfg.Store.Document()
	rt := &ObfsRuntime{}
	if f.Mode == "auto" {
		b, err := ObfsBind(cfg.Bind, doc.NetworkID, obfs.DefaultPadding())
		if err != nil {
			return nil, err
		}
		cfg.Bind, rt.Bind = b, b
	}
	if f.TLSListen != "" {
		if cfg.TCPListen == "" {
			return nil, ErrNoTCPTransport
		}
		names := f.Names
		if len(names) == 0 {
			names = defaultObfsNames(doc.Coordinator)
		}
		cert, pin, err := obfs.LoadOrCreateCertificate(dir, names, now)
		if err != nil {
			return nil, err
		}
		ln, err := net.Listen("tcp", f.TLSListen)
		if err != nil {
			return nil, fmt.Errorf("TLS gizleme portu açılamadı: %w", err)
		}
		rt.ln, rt.tls, rt.Pin = ln, obfs.ServerConfig(cert), pin
	}
	return rt, nil
}

func defaultObfsNames(c *trust.Coordinator) []string {
	if c != nil {
		if host, _, err := net.SplitHostPort(c.Endpoint); err == nil && host != "" {
			return []string{host}
		}
	}
	return []string{"localhost"}
}

// Addr is the TLS listener's address, or nil.
func (o *ObfsRuntime) Addr() net.Addr {
	if o == nil || o.ln == nil {
		return nil
	}
	return o.ln.Addr()
}

// Serve runs the TLS listener for srv until ctx ends; it is a no-op
// without one. Errors go to onErr (may be nil).
func (o *ObfsRuntime) Serve(ctx context.Context, srv *Server, onErr func(error)) {
	if o == nil || o.ln == nil || srv == nil {
		return
	}
	ln := o.ln
	o.ln = nil
	go func() {
		if err := srv.ServeObfsTLS(ctx, ln, o.tls); err != nil && onErr != nil {
			onErr(err)
		}
	}()
}

// Close releases the listener when Serve was never called.
func (o *ObfsRuntime) Close() {
	if o != nil && o.ln != nil {
		_ = o.ln.Close()
		o.ln = nil
	}
}
