package service

// Network locations (ADR-0226): the owner's switch and the device and
// share list the tray turns into Windows Explorer network locations. The
// shares come from the other devices' detailed inventories, which only
// admin devices receive; the names of devices and the network domain come
// from the signed document. The switch is on by default and lives in
// netplaces.json in the data directory.

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

var _ panel.NetPlacesControl = (*Runtime)(nil)

// NetPlacesFile holds the network location switch.
const NetPlacesFile = "netplaces.json"

type netPlacesSettings struct {
	Schema int `json:"schema"`
	// Off is stored instead of On so a missing file means on.
	Off bool `json:"off,omitempty"`
}

// LoadNetPlacesOn reads the switch; a missing file is on.
func LoadNetPlacesOn(dir string) (bool, error) {
	var s netPlacesSettings
	if err := loadJSON(filepath.Join(dir, NetPlacesFile), &s); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("ağ konumu ayarı okunamadı: %w", err)
	}
	return !s.Off, nil
}

// SaveNetPlacesOn writes the switch.
func SaveNetPlacesOn(dir string, on bool) error {
	return saveJSON(filepath.Join(dir, NetPlacesFile), netPlacesSettings{Schema: 1, Off: !on})
}

// NetPlacesStatus implements panel.NetPlacesControl.
func (r *Runtime) NetPlacesStatus() (panel.NetPlacesStatus, error) {
	on, err := LoadNetPlacesOn(r.cfg.DataDir)
	if err != nil {
		return panel.NetPlacesStatus{}, err
	}
	st := panel.NetPlacesStatus{Supported: runtime.GOOS == "windows", On: on}
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e == nil {
		return st, nil
	}
	self, err := e.Self()
	doc := e.Document()
	if err != nil || doc == nil {
		return st, nil
	}
	st.Admin = self.HasRole(trust.RoleAdmin)
	st.Ready = st.Admin
	if st.Admin {
		st.Devices = netPlaceDevices(doc, self.Name, r.Inventory(), r.cfg.Now())
		for _, d := range st.Devices {
			st.Shares += len(d.Shares)
		}
	}
	return st, nil
}

// SetNetPlaces implements panel.NetPlacesControl.
func (r *Runtime) SetNetPlaces(on bool) (panel.NetPlacesStatus, error) {
	if err := SaveNetPlacesOn(r.cfg.DataDir, on); err != nil {
		return panel.NetPlacesStatus{}, fmt.Errorf("ağ konumu ayarı kaydedilemedi: %w", err)
	}
	return r.NetPlacesStatus()
}

// netPlaceDevices lists every current device of doc except this one with
// the shares of its last detailed inventory. The host is the device's
// MagicDNS name, built from the signed document only; a device without
// an inventory is listed as not known.
func netPlaceDevices(doc *trust.Document, selfName string, inv panel.Inventory, now time.Time) []panel.NetPlaceDevice {
	if doc == nil || doc.DNSDomain == "" {
		return nil
	}
	var out []panel.NetPlaceDevice
	for _, d := range doc.Devices {
		if d.Name == selfName || !now.Before(d.ExpiresAt) {
			continue
		}
		pd := panel.NetPlaceDevice{Name: d.Name, Host: d.Name + "." + doc.DNSDomain}
		if rep, ok := inv.Devices[d.Name]; ok && rep.Info.Detail != nil {
			pd.Known = true
			pd.Shares = slices.Clone(rep.Info.Detail.Shares)
		}
		out = append(out, pd)
	}
	slices.SortFunc(out, func(a, b panel.NetPlaceDevice) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return out
}
