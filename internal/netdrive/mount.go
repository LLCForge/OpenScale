// Package netdrive makes the home network feel local (ADR-0216): network
// drive mapping to a NAS through the tunnel (#748), the Wake-on-LAN
// button through a relay device (#749) and short names such as "nas" or
// "yazici" for services (#762).
//
// A drive is only ever mapped to a device of the signed document at its
// tunnel address. Credentials never pass through OpenScale: Windows uses
// the Credential Manager entry for the server (or the signed-in user),
// macOS the Keychain (mount_smbfs -N) and Linux the desktop keyring (gio).
package netdrive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Mount is one network drive the owner configured.
type Mount struct {
	// Name is the owner's label.
	Name string `json:"name"`
	// Device is the NAS's device name in the signed document.
	Device string `json:"device"`
	// Share is the SMB share name.
	Share string `json:"share"`
	// Username is optional; the password stays in the system's vault.
	Username string `json:"username,omitempty"`
	// Letter is the Windows drive letter ("Z:").
	Letter string `json:"letter,omitempty"`
	// Point is the macOS/Linux mount point (an empty folder the user
	// owns). Linux gio mounts ignore it and use the desktop's location.
	Point string `json:"point,omitempty"`
	// Persistent keeps a Windows mapping across sign-ins.
	Persistent bool `json:"persistent,omitempty"`
	// Linux selects "gio" (default, no root, keyring) or "cifs"
	// (mount.cifs, needs root and an owner-made credentials file).
	Linux string `json:"linux,omitempty"`
	// CredentialsFile is the mount.cifs credentials file the owner made.
	CredentialsFile string `json:"credentials_file,omitempty"`
}

// Errors of drive mapping.
var (
	ErrNotTunnel   = errors.New("ağ sürücüsü yalnızca ağ belgesindeki bir cihazın tünel adresine bağlanır")
	ErrUnsupported = errors.New("bu sistemde ağ sürücüsü bağlanamıyor")
)

var (
	shareRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._$-]{0,79}$`)
	userRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@\\-]{0,63}$`)
)

// Validate checks the fields that do not depend on the document.
func (m Mount) Validate(goos string) error {
	if m.Name == "" || len(m.Name) > 64 || strings.ContainsAny(m.Name, "\r\n\t") {
		return errors.New("sürücü adı 1-64 karakter olmalı")
	}
	if !shareRe.MatchString(m.Share) || strings.Contains(m.Share, "..") {
		return fmt.Errorf("paylaşım adı geçersiz: %q", m.Share)
	}
	if m.Username != "" && !userRe.MatchString(m.Username) {
		return fmt.Errorf("kullanıcı adı geçersiz: %q", m.Username)
	}
	switch goos {
	case "windows":
		if !validLetter(m.Letter) {
			return errors.New("sürücü harfi D: ile Z: arasında olmalı")
		}
	case "darwin":
		if err := validPoint(m.Point); err != nil {
			return err
		}
	case "linux":
		switch m.Linux {
		case "", "gio":
		case "cifs":
			if err := validPoint(m.Point); err != nil {
				return err
			}
			if m.CredentialsFile != "" && (!path.IsAbs(m.CredentialsFile) || strings.ContainsAny(m.CredentialsFile, ",\r\n")) {
				return errors.New("kimlik dosyası mutlak bir yol olmalı")
			}
		default:
			return errors.New(`Linux yöntemi "gio" veya "cifs" olmalı`)
		}
	default:
		return ErrUnsupported
	}
	return nil
}

func validLetter(s string) bool {
	if len(s) != 2 || s[1] != ':' {
		return false
	}
	c := s[0] &^ 0x20
	return c >= 'D' && c <= 'Z'
}

func validPoint(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || p == "/" || strings.ContainsAny(p, "\r\n,") {
		return errors.New("bağlama noktası temiz, mutlak bir klasör yolu olmalı")
	}
	for _, sys := range []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/proc", "/sbin", "/sys", "/usr", "/var", "/System", "/Library", "/private"} {
		if p == sys || strings.HasPrefix(p, sys+"/") {
			return fmt.Errorf("bağlama noktası sistem klasörü olamaz: %s", p)
		}
	}
	return nil
}

// ResolveHost returns the NAS's tunnel address from the signed document.
// The address must lie inside the document's tunnel prefixes.
func ResolveHost(doc *trust.Document, device string) (netip.Addr, error) {
	if doc == nil {
		return netip.Addr{}, ErrNotTunnel
	}
	d, ok := doc.DeviceByName(device)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%w: %q bulunamadı", ErrNotTunnel, device)
	}
	switch {
	case d.IPv4.IsValid() && doc.IPv4Prefix.Contains(d.IPv4):
		return d.IPv4, nil
	case d.IPv6.IsValid() && doc.IPv6Prefix.Contains(d.IPv6):
		return d.IPv6, nil
	}
	return netip.Addr{}, ErrNotTunnel
}

// Command is a program and its arguments; no shell is ever used.
type Command struct {
	Path string
	Args []string
}

func hostString(a netip.Addr) string { return a.String() }

// UNC returns \\host\share for an IPv4 tunnel address. An IPv6 literal
// would need a special Windows host name, so Windows mappings use the
// device's IPv4 tunnel address only.
func UNC(host netip.Addr, share string) (string, error) {
	host = host.Unmap()
	if !host.Is4() {
		return "", errors.New("Windows ağ sürücüsü için cihazın IPv4 tünel adresi gerekli")
	}
	return `\\` + host.String() + `\` + share, nil
}

// SMBURL returns smb://[user@]host/share with every part escaped.
func SMBURL(host netip.Addr, share, user string) string {
	h := hostString(host)
	if host.Is6() {
		h = "[" + h + "]"
	}
	u := ""
	if user != "" {
		u = urlEscape(user) + "@"
	}
	return "smb://" + u + h + "/" + urlEscape(share)
}

func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// Plan returns the command that maps m on goos (macOS and Linux). Windows
// uses WNetAddConnection2W directly; see MapDrive.
func Plan(m Mount, host netip.Addr, goos string) (Command, error) {
	if err := m.Validate(goos); err != nil {
		return Command{}, err
	}
	switch goos {
	case "darwin":
		// -N: never prompt; the Keychain supplies the password.
		return Command{Path: "/sbin/mount_smbfs", Args: []string{"-N", "//" + smbAuthority(host, m.Username) + "/" + urlEscape(m.Share), m.Point}}, nil
	case "linux":
		if m.Linux == "cifs" {
			opts := []string{"vers=3.0", "seal", "nosuid", "nodev", "noexec"}
			if m.CredentialsFile != "" {
				opts = append(opts, "credentials="+m.CredentialsFile)
			} else if m.Username != "" {
				opts = append(opts, "username="+m.Username)
			}
			return Command{Path: "mount.cifs", Args: []string{"//" + hostString(host) + "/" + m.Share, m.Point, "-o", strings.Join(opts, ",")}}, nil
		}
		return Command{Path: "gio", Args: []string{"mount", SMBURL(host, m.Share, m.Username)}}, nil
	}
	return Command{}, ErrUnsupported
}

// UnmountPlan returns the command that removes m on goos (macOS, Linux).
func UnmountPlan(m Mount, host netip.Addr, goos string) (Command, error) {
	if err := m.Validate(goos); err != nil {
		return Command{}, err
	}
	switch goos {
	case "darwin":
		return Command{Path: "/sbin/umount", Args: []string{m.Point}}, nil
	case "linux":
		if m.Linux == "cifs" {
			return Command{Path: "umount", Args: []string{m.Point}}, nil
		}
		return Command{Path: "gio", Args: []string{"mount", "-u", SMBURL(host, m.Share, m.Username)}}, nil
	}
	return Command{}, ErrUnsupported
}

func smbAuthority(host netip.Addr, user string) string {
	h := hostString(host)
	if host.Is6() {
		h = "[" + h + "]"
	}
	if user == "" {
		return h
	}
	return urlEscape(user) + "@" + h
}

const commandTimeout = 30 * time.Second

func run(ctx context.Context, c Command) error {
	path, err := exec.LookPath(c.Path)
	if err != nil {
		return fmt.Errorf("%s bulunamadı: %w", c.Path, ErrUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, c.Args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("ağ sürücüsü komutu başarısız: %w (%s)", err, msg)
	}
	return nil
}

// MapDrive maps m to its NAS's tunnel address on this computer.
func MapDrive(ctx context.Context, doc *trust.Document, m Mount) error {
	host, err := ResolveHost(doc, m.Device)
	if err != nil {
		return err
	}
	if err := m.Validate(runtime.GOOS); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return mapWindows(m, host)
	}
	c, err := Plan(m, host, runtime.GOOS)
	if err != nil {
		return err
	}
	return run(ctx, c)
}

// UnmapDrive removes m.
func UnmapDrive(ctx context.Context, doc *trust.Document, m Mount) error {
	if err := m.Validate(runtime.GOOS); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return unmapWindows(m)
	}
	host, err := ResolveHost(doc, m.Device)
	if err != nil {
		return err
	}
	c, err := UnmountPlan(m, host, runtime.GOOS)
	if err != nil {
		return err
	}
	return run(ctx, c)
}
