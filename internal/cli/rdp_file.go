package cli

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// Hardened .rdp files for "connect --rdp" (#433, ADR-0146). Network level
// authentication is required and every redirection is off unless the owner
// names it in --rdp-allow; the address is the device's name inside the
// network.

// rdpRedirections maps the --rdp-allow names to their .rdp settings: the
// value when allowed and the value when not.
var rdpRedirections = map[string][3]string{
	"clipboard":  {"redirectclipboard:i:", "1", "0"},
	"drives":     {"drivestoredirect:s:", "*", ""},
	"printers":   {"redirectprinters:i:", "1", "0"},
	"smartcards": {"redirectsmartcards:i:", "1", "0"},
	"ports":      {"redirectcomports:i:", "1", "0"},
	"usb":        {"usbdevicestoredirect:s:", "*", ""},
	"camera":     {"camerastoredirect:s:", "*", ""},
	"audio":      {"audiomode:i:", "0", "2"},
	"microphone": {"audiocapturemode:i:", "1", "0"},
	"webauthn":   {"redirectwebauthn:i:", "1", "0"},
	"location":   {"redirectlocation:i:", "1", "0"},
	"pos":        {"redirectposdevices:i:", "1", "0"},
}

// parseRDPAllow reads a comma separated list of redirection names.
func parseRDPAllow(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		if _, ok := rdpRedirections[p]; !ok {
			names := make([]string, 0, len(rdpRedirections))
			for k := range rdpRedirections {
				names = append(names, k)
			}
			slices.Sort(names)
			return nil, usageError("bilinmeyen yönlendirme %q; geçerli olanlar: %s", p, strings.Join(names, ","))
		}
		out[p] = true
	}
	return out, nil
}

// rdpFileContent returns the .rdp file (CRLF lines). host may carry a
// port.
func rdpFileContent(host string, allow map[string]bool) string {
	lines := []string{
		"full address:s:" + host,
		// Network level authentication (CredSSP) is required.
		"enablecredsspsupport:i:1",
		"negotiate security layer:i:1",
		// Warn when the server certificate cannot be verified (a
		// self-signed RDP certificate is common inside a private
		// network; "1" would refuse every such server).
		"authentication level:i:2",
		"prompt for credentials:i:1",
		"promptcredentialonce:i:1",
		"remoteapplicationmode:i:0",
		"use redirection server name:i:0",
		"gatewayusagemethod:i:0",
		"devicestoredirect:s:",
	}
	names := make([]string, 0, len(rdpRedirections))
	for k := range rdpRedirections {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, n := range names {
		r := rdpRedirections[n]
		if allow[n] {
			lines = append(lines, r[0]+r[1])
		} else {
			lines = append(lines, r[0]+r[2])
		}
	}
	if !allow["drives"] {
		lines = append(lines, "redirectdrives:i:0")
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// defaultRDPFilePath is where connect keeps the generated file on Windows.
func defaultRDPFilePath(name string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	safe := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return '_'
	}, name)
	if safe == "" || strings.Trim(safe, ".") == "" {
		safe = "cihaz"
	}
	return filepath.Join(dir, "OpenScale", "rdp", safe+".rdp"), nil
}

// writeRDPFile writes the file readable only by the owner. exclusive
// refuses an existing file (a path the user gave); otherwise the file in
// OpenScale's own cache folder is replaced.
func writeRDPFile(path, content string, exclusive bool) error {
	if !strings.EqualFold(filepath.Ext(path), ".rdp") {
		return usageError("--rdp-file uzantısı .rdp olmalı")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s zaten var; üzerine yazılmaz", path)
		}
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// rdpFileCommand opens a .rdp file with the platform's client.
func rdpFileCommand(goos, path string) []string {
	switch goos {
	case "windows":
		return []string{"mstsc.exe", path}
	case "darwin":
		return []string{"open", path}
	default:
		return []string{"xfreerdp", path}
	}
}

// connectRDP opens the RDP client. On Windows, and whenever --rdp-file is
// given, it goes through a hardened .rdp file (#433) that names the device
// inside the network; elsewhere the client gets the address directly.
func connectRDP(env *Env, rc remoteContext, name, hostport string, port int, file, allowList string, printOnly bool) error {
	allow, err := parseRDPAllow(allowList)
	if err != nil {
		return err
	}
	if file == "" && runtime.GOOS != "windows" {
		if len(allow) > 0 {
			return usageError("--rdp-allow yalnızca .rdp dosyasıyla geçerlidir (--rdp-file)")
		}
		return launch(env, rdpCommand(runtime.GOOS, hostport), printOnly)
	}
	host := hostport
	if rc.doc != nil && name != "" && rc.doc.DNSDomain != "" {
		host = name + "." + rc.doc.DNSDomain
		if port != 3389 {
			host = net.JoinHostPort(host, strconv.Itoa(port))
		}
	}
	content := rdpFileContent(host, allow)
	exclusive := file != ""
	if file == "" {
		if file, err = defaultRDPFilePath(cmp.Or(name, hostport)); err != nil {
			return fmt.Errorf(".rdp dosyası için klasör bulunamadı: %w", err)
		}
	}
	argv := rdpFileCommand(runtime.GOOS, file)
	if printOnly {
		fmt.Fprint(env.Stdout, content)
		fmt.Fprintln(env.Stdout, strings.Join(argv, " "))
		return nil
	}
	if err := writeRDPFile(file, content, exclusive); err != nil {
		return err
	}
	if len(allow) > 0 {
		names := make([]string, 0, len(allow))
		for k := range allow {
			names = append(names, k)
		}
		slices.Sort(names)
		fmt.Fprintf(env.Stderr, "uyarı: açık yönlendirmeler: %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(env.Stdout, "Sertleştirilmiş .rdp dosyası: %s (NLA zorunlu, yönlendirmeler kapalı)\n", file)
	return launch(env, argv, false)
}
