package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Resuming the setup wizard (#792). The steps themselves are read from the
// network folder every time (readSetupState): the root key, the backup
// records, the coordinator pin and the devices. The progress record only
// remembers which steps the owner chose to skip and when, so the next run
// can say where it stopped. It holds step names and a time, never a
// passphrase, a key or a backup path.

const (
	setupProgressFile    = "setup-progress.json"
	maxSetupProgressFile = 4 << 10
	setupProgressSchema  = 1

	setupStepBackup      = "backup"
	setupStepCoordinator = "coordinator"
	setupStepFirstDevice = "first-device"
)

// setupStepTitles are the Turkish names of the steps.
var setupStepTitles = map[string]string{
	setupStepBackup:      "Kök anahtar yedeği",
	setupStepCoordinator: "Koordinatör",
	setupStepFirstDevice: "İlk cihaz",
}

// setupProgress is the content of setupProgressFile.
type setupProgress struct {
	Schema    int       `json:"schema"`
	UpdatedAt time.Time `json:"updated_at"`
	Skipped   []string  `json:"skipped,omitempty"`
}

// mark records a step as skipped or no longer skipped.
func (p *setupProgress) mark(step string, skipped bool) {
	p.Skipped = slices.DeleteFunc(p.Skipped, func(s string) bool { return s == step })
	if skipped {
		p.Skipped = append(p.Skipped, step)
		slices.Sort(p.Skipped)
	}
}

// readSetupProgress reads the record; a missing or damaged one is empty.
func readSetupProgress(dir string) setupProgress {
	p := setupProgress{Schema: setupProgressSchema}
	data, err := securefile.ReadPrivate(filepath.Join(dir, setupProgressFile), maxSetupProgressFile)
	if err != nil {
		return p
	}
	var got setupProgress
	if json.Unmarshal(data, &got) != nil || got.Schema != setupProgressSchema {
		return p
	}
	for _, s := range got.Skipped {
		if _, known := setupStepTitles[s]; known && !slices.Contains(p.Skipped, s) {
			p.Skipped = append(p.Skipped, s)
		}
	}
	slices.Sort(p.Skipped)
	p.UpdatedAt = got.UpdatedAt
	return p
}

// saveSetupProgress writes the record next to the network; failing to
// write it only costs the resume note, so it warns and goes on.
func saveSetupProgress(env *Env, dir string, p setupProgress) {
	p.Schema = setupProgressSchema
	p.UpdatedAt = env.Now().UTC().Truncate(time.Second)
	data, err := json.Marshal(p)
	if err != nil {
		return
	}
	if err := securefile.Replace(filepath.Join(dir, setupProgressFile), data); err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: kurulum ilerlemesi kaydedilemedi: %v\n", err)
	}
}

// missingSteps lists the steps that are not done yet, in order.
func missingSteps(st setupState) []string {
	var out []string
	if !st.network {
		out = append(out, "Ağ ve kök anahtar")
	}
	if st.backups == 0 {
		out = append(out, setupStepTitles[setupStepBackup])
	}
	if !st.coordinator {
		out = append(out, setupStepTitles[setupStepCoordinator])
	}
	if st.devices == 0 && st.invites == 0 {
		out = append(out, setupStepTitles[setupStepFirstDevice])
	}
	return out
}

func printMissingSteps(w io.Writer, st setupState) {
	missing := missingSteps(st)
	if len(missing) == 0 {
		fmt.Fprintln(w, "Eksik adım yok; kurulum tamam.")
		return
	}
	fmt.Fprintf(w, "Eksik adımlar (%d): %s\n", len(missing), strings.Join(missing, ", "))
}

// printResumeNote says where the wizard continues. A network whose root
// key exists without a backup always starts at the backup: losing that
// computer would lose the network.
func printResumeNote(w io.Writer, st setupState, p setupProgress) {
	if !st.network {
		return
	}
	if st.backups == 0 {
		fmt.Fprintln(w, "\nKaldığınız yerden devam: kök anahtar var ama yedeği yok. Önce yedek adımı açılıyor.")
	}
	var skipped []string
	for _, s := range p.Skipped {
		if stepStillMissing(st, s) {
			skipped = append(skipped, setupStepTitles[s])
		}
	}
	if len(skipped) > 0 && !p.UpdatedAt.IsZero() {
		fmt.Fprintf(w, "Geçen sefer (%s) atlanan adımlar: %s\n", formatTime(p.UpdatedAt), strings.Join(skipped, ", "))
	}
}

func stepStillMissing(st setupState, step string) bool {
	switch step {
	case setupStepBackup:
		return st.backups == 0
	case setupStepCoordinator:
		return !st.coordinator
	case setupStepFirstDevice:
		return st.devices == 0 && st.invites == 0
	}
	return false
}
