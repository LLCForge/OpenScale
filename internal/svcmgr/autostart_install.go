package svcmgr

import (
	"errors"
	"io/fs"
	"os"
)

// installSystemAutostart writes the all-users sign-in entry during
// "service install" of the device role (ADR-0194). A file someone else
// wrote is left alone; a failure is a note, not an error: the service
// itself starts at boot either way.
func installSystemAutostart(s sysOps, goos, bin string) []string {
	p, err := SystemAutostartPath(goos)
	if err != nil {
		return nil
	}
	data, err := RenderAutostart(goos, bin)
	if err != nil {
		return []string{"Oturum açılışı kaydı yazılamadı: " + err.Error()}
	}
	full := s.path(p)
	if old, err := os.ReadFile(full); err == nil && !hasAutostartMarker(old) {
		return []string{p + " OpenScale tarafından yazılmamış; oturum açılışı kaydına dokunulmadı."}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return []string{"Oturum açılışı kaydı okunamadı: " + err.Error()}
	}
	removeLegacyAutostart(full)
	if err := writeFile(s, p, data, 0o644); err != nil {
		return []string{"Oturum açılışı kaydı yazılamadı: " + err.Error()}
	}
	return []string{"Masaüstü oturumu açılınca tepsi başlar (" + p + "); kapatmak için: openscale autostart off"}
}

// removeSystemAutostart deletes the all-users entry during "service
// uninstall" when OpenScale wrote it.
func removeSystemAutostart(s sysOps, goos string) ([]string, error) {
	p, err := SystemAutostartPath(goos)
	if err != nil {
		return nil, nil
	}
	legacy := removeLegacyAutostart(s.path(p))
	removed, err := removeAutostartFile(s.path(p))
	removed = removed || legacy
	if err != nil {
		// Someone else's file is reported, not an error of the uninstall.
		return []string{err.Error()}, nil
	}
	if removed {
		return []string{p + " kaldırıldı."}, nil
	}
	return nil, nil
}
