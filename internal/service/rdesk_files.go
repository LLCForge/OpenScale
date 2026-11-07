package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// maxRDeskFileRoots bounds the folders of the session file browser
// (ADR-0146 #435).
const maxRDeskFileRoots = 8

// ValidateRDeskFileRoots checks the owner's folders: absolute, clean, no
// duplicates and no filesystem root (a whole drive is never offered).
func ValidateRDeskFileRoots(roots []string) error {
	if len(roots) > maxRDeskFileRoots {
		return fmt.Errorf("en fazla %d klasör seçilebilir", maxRDeskFileRoots)
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if r == "" || len(r) > 1024 || strings.ContainsAny(r, "\x00\n\r") {
			return errors.New("geçersiz klasör yolu")
		}
		if !filepath.IsAbs(r) || filepath.Clean(r) != r {
			return fmt.Errorf("klasör mutlak ve sade bir yol olmalı: %q", r)
		}
		if filepath.Dir(r) == r {
			return fmt.Errorf("bir sürücünün veya dosya sisteminin kökü seçilemez: %q", r)
		}
		key := strings.ToLower(r)
		if seen[key] {
			return fmt.Errorf("klasör iki kez seçildi: %q", r)
		}
		seen[key] = true
	}
	return nil
}
