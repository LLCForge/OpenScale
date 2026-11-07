package p2psend

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/filesend"
)

// Quarantine lists and releases received files (#659). Files stay in the
// quarantine directory, marked as coming from another computer, until the
// user releases them into the inbox after a warning; releasing keeps the
// operating system's mark, so the system still warns when it is opened.
type Quarantine struct {
	Dir   string
	Inbox string
}

// QuarantinedFile is one file waiting in quarantine.
type QuarantinedFile struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	Received   time.Time `json:"received"`
	Executable bool      `json:"executable"`
	Marked     bool      `json:"marked"`
	Warning    string    `json:"warning"`
}

// ErrNotInQuarantine is returned for an unknown name.
var ErrNotInQuarantine = errors.New("karantinada böyle bir dosya yok")

// List returns the waiting files, newest first.
func (q Quarantine) List() ([]QuarantinedFile, error) {
	entries, err := os.ReadDir(q.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := []QuarantinedFile{}
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		f := QuarantinedFile{Name: e.Name(), Size: info.Size(), Received: info.ModTime(),
			Executable: filesend.IsExecutable(e.Name()), Marked: filesend.IsQuarantined(filepath.Join(q.Dir, e.Name()))}
		f.Warning = Warning(f.Name)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Received.After(out[j].Received) })
	return out, nil
}

// Warning is the text shown before a file is opened.
func Warning(name string) string {
	if filesend.IsExecutable(name) {
		return "Bu dosya açıldığında kod çalıştırabilir. Göndereni tanısanız bile, beklemediğiniz bir dosyaysa açmayın."
	}
	return "Bu dosya başka bir cihazdan geldi. Açmadan önce göndereni ve dosyayı beklediğinizi doğrulayın."
}

func (q Quarantine) path(name string) (string, error) {
	clean, err := filesend.SanitizeName(name)
	if err != nil || clean != name {
		return "", ErrNotInQuarantine
	}
	p := filepath.Join(q.Dir, name)
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() {
		return "", ErrNotInQuarantine
	}
	return p, nil
}

// Release moves a file into the inbox and returns its new path. The
// operating system mark moves with it on the same volume.
func (q Quarantine) Release(name string) (string, error) {
	src, err := q.path(name)
	if err != nil {
		return "", err
	}
	if q.Inbox == "" {
		return "", errors.New("gelen kutusu klasörü ayarlı değil")
	}
	if err := os.MkdirAll(q.Inbox, 0o700); err != nil {
		return "", err
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 0; i <= maxCollisions; i++ {
		cand := name
		if i > 0 {
			cand = fmt.Sprintf("%s (%d)%s", base, i, ext)
		}
		dst := filepath.Join(q.Inbox, cand)
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return "", err
		}
		if !filesend.IsQuarantined(dst) {
			_ = filesend.MarkQuarantine(dst, "openscale")
		}
		return dst, nil
	}
	return "", errors.New("çok fazla aynı adlı dosya")
}

// Remove deletes a quarantined file.
func (q Quarantine) Remove(name string) error {
	p, err := q.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
