package coordinator

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
)

// RAM mode (#633, ADR-0182). The coordinator runs with its state directory
// on tmpfs: nothing it learns is written to a disk, so a seized or imaged
// server holds no document history, no relay usage and no objects. On
// start the directory is filled from a read-only seed (SeedStateDir): the
// anchor, a document (any valid version) and the coordinator key, ideally
// from systemd credentials sealed to the server's TPM
// (LoadCredentialEncrypted=). The newest document comes back from the
// devices, which upload it when the coordinator is behind (node/engine.go);
// the canary and sealed blobs come back the same way (any member may
// re-upload a signed object). With the hardening file's ram_only the
// coordinator refuses to start on a disk-backed directory (fail closed).

// SeedFiles are the files SeedStateDir copies when present.
var SeedFiles = []string{"anchor.json", "network.json", "state.json", "root.json", "coordinator.key", HardeningFile, RelayAdmissionFile, "warrant-canary.json"}

const maxSeedFile = 4 << 20

// SeedStateDir copies the seed files into state (created 0700). Existing
// files in state are kept: a restart of the service without a reboot keeps
// the newer document it already has. It returns the copied names.
func SeedStateDir(seed, state string) ([]string, error) {
	if seed == "" || state == "" {
		return nil, errors.New("seed and state directories are required")
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	var copied []string
	for _, name := range SeedFiles {
		dst := filepath.Join(state, name)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		data, err := securefile.ReadLimited(filepath.Join(seed, name), maxSeedFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return copied, fmt.Errorf("seed %s: %w", name, err)
		}
		if err := securefile.Replace(dst, data); err != nil {
			wipe(data)
			return copied, fmt.Errorf("seed %s: %w", name, err)
		}
		wipe(data)
		copied = append(copied, name)
	}
	return copied, nil
}

// wipe zeroes b (key material copied through memory).
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
