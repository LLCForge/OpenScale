package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
)

// Staging of files dropped on the panel's send page (ADR-0204). Each file
// gets its own random folder under e2e/giden so two drops with the same
// name never meet, and staged copies older than a day are removed on the
// next drop: a send that has not finished by then is restarted from the
// panel anyway.

const (
	e2eStageDir = "giden"
	e2eStageTTL = 24 * time.Hour
)

var _ panel.E2EStager = (*Runtime)(nil)

// E2EStage implements panel.E2EStager.
func (r *Runtime) E2EStage(name string, body io.Reader) (string, error) {
	clean, err := filesend.SanitizeName(name)
	if err != nil || clean != name {
		return "", panel.ErrE2EStageName
	}
	root := r.path(e2eDirName, e2eStageDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	r.pruneE2EStage(root)
	var rnd [12]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return "", err
	}
	dir := filepath.Join(root, hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, clean)
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	_, cerr := io.Copy(f, body)
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("stage %w", cerr)
	}
	return dst, nil
}

// pruneE2EStage removes staged folders older than e2eStageTTL. Only the
// random folders this file creates are touched.
func (r *Runtime) pruneE2EStage(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	now := time.Now()
	if r.cfg.Now != nil {
		now = r.cfg.Now()
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 24 {
			continue
		}
		if _, err := hex.DecodeString(e.Name()); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < e2eStageTTL {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			r.logger.Warn("stale e2e staging not removed", "error", err.Error())
		}
	}
}
