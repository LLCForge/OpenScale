//go:build windows

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/netdrive"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/winapp"
)

// Network locations from the tray (ADR-0226). The tray runs in the user's
// session, so it writes the locations into that user's Network Shortcuts
// folder; the service only says which devices and shares exist and
// whether the owner's switch is on.

const (
	netPlacesFirst = 20 * time.Second
	netPlacesEvery = time.Minute
	// maxNetPlacesReply bounds the device list (1024 devices with 64
	// shares each stay well below it).
	maxNetPlacesReply = 8 << 20
)

// netPlaces asks the service for the device and share list.
func (c *trayClient) netPlaces(ctx context.Context) (panel.NetPlacesStatus, error) {
	var st panel.NetPlacesStatus
	token, err := service.ReadToken(c.dataDir)
	if err != nil {
		return st, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, panelBase+"/api/app/tray/netplaces", nil)
	if err != nil {
		return st, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("servis yanıtı: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxNetPlacesReply+1))
	if err != nil {
		return st, err
	}
	if len(data) > maxNetPlacesReply {
		return st, errors.New("ağ konumu listesi çok büyük")
	}
	return st, json.Unmarshal(data, &st)
}

// startNetPlaces keeps the user's network locations in step with the
// network until ctx ends.
func startNetPlaces(ctx context.Context, client *trayClient, tray *winapp.Tray) {
	notify := func(m string) { tray.Notify("OpenScale", m) }
	places, err := netdrive.DefaultPlaces(winapp.WriteLink)
	if err != nil {
		return
	}
	go func() {
		timer := time.NewTimer(netPlacesFirst)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			syncNetPlaces(ctx, client, places, notify)
			timer.Reset(netPlacesEvery)
		}
	}()
}

// syncNetPlaces runs one round. Nothing changes while the service cannot
// be asked or the tunnel has no document, so a restart never empties the
// locations.
func syncNetPlaces(ctx context.Context, client *trayClient, places *netdrive.Places, notify func(string)) {
	st, err := client.netPlaces(ctx)
	if err != nil || !st.Supported {
		return
	}
	if !st.On {
		if res, err := places.RemoveAll(); err == nil && len(res.Removed) > 0 {
			notify(fmt.Sprintf("OpenScale'in eklediği %d ağ konumu kaldırıldı.", len(res.Removed)))
		}
		return
	}
	if !st.Ready {
		return
	}
	devs := make([]netdrive.PlaceDevice, 0, len(st.Devices))
	for _, d := range st.Devices {
		devs = append(devs, netdrive.PlaceDevice{Name: d.Name, Host: d.Host, Known: d.Known, Shares: d.Shares})
	}
	res, err := places.Sync(devs)
	if err != nil {
		return
	}
	if n := len(res.Added); n > 0 {
		notify(fmt.Sprintf("%d ağ konumu eklendi: Dosya Gezgini > Bu bilgisayar > Ağdaki konumlar.", n))
	}
}
