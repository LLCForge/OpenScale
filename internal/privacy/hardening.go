package privacy

import (
	"os"
	"strings"
)

// HardeningStatus describes what HardenProcess did for this process.
type HardeningStatus struct {
	// CoreDumpsDisabled is true when the operating system will not write a
	// memory image of this process to disk after a crash.
	CoreDumpsDisabled bool `json:"core_dumps_disabled"`
	// Measures lists the applied measures in Turkish, for the report.
	Measures []string `json:"measures"`
	// Warnings lists what could not be applied or what the environment
	// overrides (for example GOTRACEBACK=crash).
	Warnings []string `json:"warnings,omitempty"`
}

// HardenProcess turns off crash dumps for the running process so keys in
// memory never land on disk with a dump (#45). It changes only this
// process (and the children that inherit its limits), never a system
// setting, and is safe to call more than once.
func HardenProcess() HardeningStatus {
	st := hardenProcess()
	if w := tracebackWarning(os.Getenv("GOTRACEBACK")); w != "" {
		st.Warnings = append(st.Warnings, w)
	}
	return st
}

// tracebackWarning explains a GOTRACEBACK value that asks the Go runtime
// for a dump; the runtime reads it before main runs, so it can only be
// reported, not undone.
func tracebackWarning(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "crash":
		return "GOTRACEBACK=crash ayarlı: Go çalışma zamanı çökmede döküm ister; işletim sistemi sınırı bunu engeller ama değişkeni kaldırın"
	case "wer":
		return "GOTRACEBACK=wer ayarlı: Windows Hata Bildirimi açılır; yığın (heap) döküme alınmaz ama değişkeni kaldırın"
	}
	return ""
}
