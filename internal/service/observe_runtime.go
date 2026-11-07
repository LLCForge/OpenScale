package service

import (
	"context"
	"path/filepath"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// The desktop service's observability (ADR-0105). The audit log and the
// switches live in the data directory, which only SYSTEM and the
// administrators can read (ADR-0014).

// serviceLogPath is where the desktop service writes its log
// (internal/desktop).
var serviceLogPath = filepath.Join("logs", "service.log")

// maxSettingsForBundle bounds the settings file read for the bundle.
const maxSettingsForBundle = 256 << 10

var _ panel.ObservabilitySource = (*Runtime)(nil)

// observer returns the service's Observer, created on first use.
func (r *Runtime) observer() *Observer {
	r.diag.obsOnce.Do(func() {
		r.diag.obs = NewObserver(ObserverConfig{
			Dir:         r.cfg.DataDir,
			Engine:      r.currentEngine,
			Now:         r.cfg.Now,
			Logger:      r.logger,
			Status:      r.Status,
			Interface:   r.tunnelInterface,
			BundleExtra: r.bundleExtra,
		})
	})
	return r.diag.obs
}

// Observability implements panel.ObservabilitySource.
func (r *Runtime) Observability() panel.Observability { return r.observer() }

// bundleExtra adds the settings (secrets removed) and the end of the
// service log to the diagnostics bundle.
func (r *Runtime) bundleExtra(context.Context) []panel.BundleFile {
	var out []panel.BundleFile
	if data, err := securefile.ReadLimited(r.path(settingsFile), maxSettingsForBundle); err == nil {
		out = append(out, panel.BundleFile{Name: "settings.json", Content: RedactJSON(data) + "\n"})
	}
	for _, p := range []string{r.path(serviceLogPath + ".1"), r.path(serviceLogPath)} {
		if s, err := tailFile(p, maxBundleFile/2); err == nil {
			out = append(out, panel.BundleFile{Name: "logs/" + filepath.Base(p), Content: s})
		}
	}
	return out
}

// auditLocal records a change the owner made through the local API.
func (r *Runtime) auditLocal(kind, message string) {
	r.observer().Security(kind, audit.SeverityInfo, panel.CategorySecurity, "", message, false)
}
