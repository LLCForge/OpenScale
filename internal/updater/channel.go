package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

// Update channel (ADR-0193). A pre-release ("-beta.N" or any other
// SemVer pre-release) is installed only when the user chose the beta
// channel: Options.AllowPrerelease for one run, or "openscale update
// channel beta" which saves channel.json next to the journal. The file is
// in the administrator-only update directory, like the journal.

// ChannelFile holds the saved channel in Options.StateDir.
const ChannelFile = "channel.json"

const maxChannelFile = 1 << 10

// Channels.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// ErrPrerelease: the candidate is a pre-release and the beta channel is
// not chosen.
var ErrPrerelease = errors.New("aday sürüm bir önsürüm (beta); önsürümler yalnızca beta kanalı seçildiyse kurulur")

type channelFile struct {
	Channel string `json:"channel"`
}

// ParseChannel accepts stable or beta (and their Turkish names).
func ParseChannel(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "stable", "kararlı", "kararli":
		return ChannelStable, nil
	case "beta", "önsürüm", "onsurum":
		return ChannelBeta, nil
	}
	return "", fmt.Errorf("kanal %q geçersiz; stable veya beta yazın", s)
}

// ReadChannel returns the saved channel; a missing file is stable. A
// damaged file is an error and the caller treats it as stable.
func ReadChannel(stateDir string) (string, error) {
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, ChannelFile), maxChannelFile)
	if errors.Is(err, fs.ErrNotExist) {
		return ChannelStable, nil
	}
	if err != nil {
		return ChannelStable, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f channelFile
	if err := dec.Decode(&f); err != nil {
		return ChannelStable, fmt.Errorf("%s bozuk: %w", ChannelFile, err)
	}
	ch, err := ParseChannel(f.Channel)
	if err != nil {
		return ChannelStable, err
	}
	return ch, nil
}

// WriteChannel saves the channel.
func WriteChannel(stateDir, channel string) error {
	ch, err := ParseChannel(channel)
	if err != nil {
		return err
	}
	data, err := json.Marshal(channelFile{Channel: ch})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(stateDir, ChannelFile), data)
}

// IsPrerelease reports whether v has a SemVer pre-release part.
func IsPrerelease(v string) bool {
	pv, err := release.ParseVersion(v)
	return err == nil && len(pv.Pre) > 0
}

// CheckChannel refuses a pre-release candidate unless allowed.
func CheckChannel(candidate string, allowPrerelease bool) error {
	if IsPrerelease(candidate) && !allowPrerelease {
		return fmt.Errorf("%w (%s); beta kanalına geçmek için: openscale update channel beta", ErrPrerelease, candidate)
	}
	return nil
}

// prereleaseAllowed combines the per-run option and the saved channel.
func prereleaseAllowed(opts Options) bool {
	if opts.AllowPrerelease {
		return true
	}
	ch, err := ReadChannel(opts.StateDir)
	return err == nil && ch == ChannelBeta
}
