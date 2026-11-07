package winapp

import "errors"

// Windows Server Core (#493). Server Core has no Explorer shell: no
// notification area, no default browser. The service and the command line
// work unchanged; the tray refuses to start with ErrNoDesktopShell, which
// names the command line flow (docs/windows-server-core.md).

// ErrNoDesktopShell is returned by the tray on Server Core.
var ErrNoDesktopShell = errors.New("bu Windows sürümünde masaüstü kabuğu yok (Server Core): tepsi simgesi açılmaz. " +
	"Kurulum ve yönetim komut satırıyla yapılır: 'openscale service install', 'openscale invite-join <kod>' veya 'openscale join <paket>', " +
	"ayarlar için 'openscale set', durum için 'openscale status'; panel için başka bir bilgisayardan uzak panel (ADR-0107) kullanılabilir")

// serverCoreType is the InstallationType value of Server Core.
const serverCoreType = "Server Core"

// isServerCoreType reports whether an InstallationType value (registry
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion) means Server Core.
// Nano Server is reported as "Nano Server" and also has no shell.
func isServerCoreType(t string) bool {
	return t == serverCoreType || t == "Nano Server"
}
