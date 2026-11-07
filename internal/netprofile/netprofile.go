// Package netprofile keeps one device state directory per network so a
// device can be a member of several OpenScale networks (F-109, #291,
// ADR-0135), for example a personal network and a family network, each
// with its own root key and its own owner.
//
// Layout under the per-user base directory:
//
//	<base>/                    the "default" profile (the pre-profile layout)
//	<base>/networks/<name>/    one more profile per network
//	<base>/networks/active     the name of the active profile
//
// Every profile is a complete, independent member state directory: its own
// anchor, document, rollback state and device keys. Nothing is shared, so
// the single-owner rule holds per network and a document signed by one
// root can never be accepted into another profile (member.JoinAnchor
// already refuses a foreign anchor). Exactly one profile is active at a
// time; without the pointer file the default profile is active, so
// existing installations keep working unchanged.
package netprofile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
)

// DefaultName names the profile stored directly in the base directory.
const DefaultName = "default"

const (
	networksDir = "networks"
	activeFile  = "active"
	// MaxNameLen bounds a profile name.
	MaxNameLen = 32
	// MaxProfiles bounds the profiles listed and created.
	MaxProfiles = 64
	maxActive   = 128
)

var (
	// ErrUnknown is returned for a profile that does not exist.
	ErrUnknown = errors.New("no such network profile")
	// ErrNotJoined is returned when switching to a profile that has not
	// joined a network yet.
	ErrNotJoined = errors.New("network profile has not joined a network")
)

// ValidName checks a profile name: 1-32 lowercase letters, digits and
// hyphens, starting with a letter or digit. "active" is reserved.
func ValidName(name string) error {
	if name == "" || len(name) > MaxNameLen || name == activeFile {
		return fmt.Errorf("invalid network profile name %q", name)
	}
	for i, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0)
		if !ok {
			return fmt.Errorf("invalid network profile name %q: use a-z, 0-9 and '-'", name)
		}
	}
	return nil
}

// Dir returns the state directory of the named profile.
func Dir(base, name string) (string, error) {
	if base == "" {
		return "", errors.New("empty base directory")
	}
	if err := ValidName(name); err != nil {
		return "", err
	}
	if name == DefaultName {
		return base, nil
	}
	return filepath.Join(base, networksDir, name), nil
}

// Active returns the name of the active profile. A missing pointer means
// the default profile; a damaged pointer is an error instead of a silent
// fallback, so commands never act on the wrong network.
func Active(base string) (string, error) {
	data, err := securefile.ReadLimited(filepath.Join(base, networksDir, activeFile), maxActive)
	if errors.Is(err, fs.ErrNotExist) {
		return DefaultName, nil
	}
	if err != nil {
		return "", fmt.Errorf("read active network profile: %w", err)
	}
	name := strings.TrimSpace(string(data))
	if err := ValidName(name); err != nil {
		return "", fmt.Errorf("active network profile pointer is damaged: %w", err)
	}
	return name, nil
}

// Resolve returns the state directory for name, or for the active profile
// when name is empty. A named profile other than the default must exist
// unless create is set, in which case its directory is created (0700).
func Resolve(base, name string, create bool) (string, error) {
	if name == "" {
		active, err := Active(base)
		if err != nil {
			return "", err
		}
		name = active
	}
	dir, err := Dir(base, name)
	if err != nil {
		return "", err
	}
	if name == DefaultName {
		return dir, nil
	}
	st, err := os.Stat(dir)
	switch {
	case err == nil && st.IsDir():
		return dir, nil
	case err == nil:
		return "", fmt.Errorf("network profile %q is not a directory", name)
	case !errors.Is(err, fs.ErrNotExist):
		return "", err
	case !create:
		return "", fmt.Errorf("%w: %q", ErrUnknown, name)
	}
	if n, err := names(base); err == nil && len(n) >= MaxProfiles {
		return "", fmt.Errorf("at most %d network profiles are allowed", MaxProfiles)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create network profile: %w", err)
	}
	return dir, nil
}

// Profile describes one network profile.
type Profile struct {
	Name   string
	Dir    string
	Active bool
	// Joined is true when the directory holds a verified membership.
	Joined      bool
	NetworkID   string
	DisplayName string
	// Duplicate is true when another profile belongs to the same network.
	Duplicate bool
	// Problem describes why a profile directory could not be opened.
	Problem string
}

// names returns the profile names that exist on disk, default first.
func names(base string) ([]string, error) {
	out := []string{DefaultName}
	entries, err := os.ReadDir(filepath.Join(base, networksDir))
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || ValidName(e.Name()) != nil || e.Name() == DefaultName {
			continue
		}
		out = append(out, e.Name())
		if len(out) >= MaxProfiles {
			break
		}
	}
	slices.Sort(out[1:])
	return out, nil
}

// List returns every profile with its membership.
func List(base string) ([]Profile, error) {
	if base == "" {
		return nil, errors.New("empty base directory")
	}
	active, activeErr := Active(base)
	all, err := names(base)
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(all))
	byNet := map[string]int{}
	for _, name := range all {
		dir, err := Dir(base, name)
		if err != nil {
			continue
		}
		p := Profile{Name: name, Dir: dir, Active: activeErr == nil && name == active}
		s, err := member.Open(dir)
		switch {
		case errors.Is(err, member.ErrNotJoined):
		case err != nil:
			p.Problem = err.Error()
		default:
			doc := s.Document()
			p.Joined = true
			p.NetworkID = s.Anchor().NetworkID
			if doc != nil {
				p.DisplayName = doc.DisplayName
			}
			byNet[p.NetworkID]++
		}
		out = append(out, p)
	}
	for i := range out {
		if out[i].Joined && byNet[out[i].NetworkID] > 1 {
			out[i].Duplicate = true
		}
	}
	return out, activeErr
}

// Switch makes name the active profile. Only a profile with a verified
// membership can become active; the pointer is replaced atomically.
func Switch(base, name string) error {
	dir, err := Resolve(base, name, false)
	if err != nil {
		return err
	}
	if _, err := member.Open(dir); err != nil {
		if errors.Is(err, member.ErrNotJoined) {
			return fmt.Errorf("%w: %q", ErrNotJoined, name)
		}
		return fmt.Errorf("network profile %q: %w", name, err)
	}
	ptr := filepath.Join(base, networksDir, activeFile)
	if name == DefaultName {
		if err := os.Remove(ptr); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return securefile.Replace(ptr, []byte(name+"\n"))
}
