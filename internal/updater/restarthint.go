package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Restart hint (#203, ADR-0235). Apply and ApplyPackage write it into the
// state folder right before they stop the services and remove it when the
// update ends. A stopping service that finds it knows the stop is an
// update: it keeps the kill switch (it does anyway unless the owner asked
// to close OpenScale) and, on Linux, keeps the tunnel interface for the new
// process. The hint only ever keeps protections in place, so a stale one
// can do no harm; it still expires after RestartHintMaxAge.

// RestartHintFile is the hint's name in the updater's state folder.
const RestartHintFile = "restart-for-update.json"

// RestartHintMaxAge bounds how long a hint counts.
const RestartHintMaxAge = 10 * time.Minute

type restartHint struct {
	To string    `json:"to"`
	At time.Time `json:"at"`
}

func writeRestartHint(stateDir, to string, now time.Time) func() {
	if stateDir == "" {
		return func() {}
	}
	path := filepath.Join(stateDir, RestartHintFile)
	data, err := json.Marshal(restartHint{To: to, At: now.UTC()})
	if err == nil {
		if err = os.MkdirAll(stateDir, 0o700); err == nil {
			err = securefile.Replace(path, data)
		}
	}
	if err != nil {
		return func() {}
	}
	return func() { _ = os.Remove(path) }
}

// RestartForUpdate reports whether a service stopping now is being
// restarted by an update.
func RestartForUpdate(stateDir string, now time.Time) bool {
	if stateDir == "" {
		return false
	}
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, RestartHintFile), 4096)
	if err != nil {
		return false
	}
	var h restartHint
	if json.Unmarshal(data, &h) != nil {
		return false
	}
	age := now.Sub(h.At)
	return age >= -time.Minute && age <= RestartHintMaxAge
}
