package webview

import (
	"errors"
	"path/filepath"
	"strings"
)

// maxDataDirBytes keeps the folder well inside MAX_PATH-limited APIs of
// the web engines.
const maxDataDirBytes = 200

// checkDataDir validates a DataDir override.
func checkDataDir(dir string) error {
	if !filepath.IsAbs(dir) || len(dir) > maxDataDirBytes || strings.ContainsAny(dir, "\x00\r\n\"*?<>|") {
		return errors.New("webview: DataDir mutlak, kısa ve özel karakter içermeyen bir yol olmalı")
	}
	if filepath.Clean(dir) != dir {
		return errors.New("webview: DataDir temiz bir yol olmalı")
	}
	return nil
}
