package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
)

// reconnectCheckEvery is how often the service looks at a timed
// disconnect. It compares wall-clock times, so a computer that slept past
// the deadline reconnects right after waking.
const reconnectCheckEvery = 15 * time.Second

// morningHour is the local hour "until tomorrow morning" ends at.
const morningHour = 8

// disconnectDeadline returns when a timed disconnect of the given panel
// choice ends. now is taken in the computer's local time zone.
func disconnectDeadline(choice string, now time.Time) (time.Time, error) {
	switch choice {
	case panel.Disconnect5Min:
		return now.Add(5 * time.Minute), nil
	case panel.Disconnect1Hour:
		return now.Add(time.Hour), nil
	case panel.DisconnectMorning:
		local := now.Local()
		t := time.Date(local.Year(), local.Month(), local.Day(), morningHour, 0, 0, 0, local.Location())
		// "Tomorrow morning" is never less than an hour away: at 07:30 it
		// means the next day, at 02:00 the same day's morning.
		for !t.After(now.Add(time.Hour)) {
			t = t.AddDate(0, 0, 1)
		}
		return t, nil
	}
	return time.Time{}, errors.New("bilinmeyen süre seçimi")
}

// DisconnectFor implements panel.App: it turns the tunnel off and back on
// after the chosen time (F-121). The deadline is saved, so it survives a
// service restart.
func (r *Runtime) DisconnectFor(choice string) error {
	until, err := disconnectDeadline(choice, r.cfg.Now())
	if err != nil {
		return err
	}
	return r.setConnected(false, &until)
}

// reconnectLoop turns the tunnel back on when a timed disconnect ends.
func (r *Runtime) reconnectLoop(ctx context.Context) {
	every := reconnectCheckEvery
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < every {
		every = r.cfg.PollInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconnectIfDue()
		}
	}
}

// reconnectIfDue turns the tunnel on when its timed disconnect has ended.
// It reports whether it did.
func (r *Runtime) reconnectIfDue() bool {
	st, err := r.currentSettings()
	if err != nil || !st.Disconnected || st.DisconnectedUntil == nil || r.cfg.Now().Before(*st.DisconnectedUntil) {
		return false
	}
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		// Nothing to reconnect; forget the deadline.
		_ = r.updateSettings(func(st *settings) (bool, error) {
			st.Disconnected, st.DisconnectedUntil = false, nil
			return true, nil
		})
		return false
	}
	r.logger.Info("timed disconnect ended")
	if err := r.setConnected(true, nil); err != nil {
		r.logger.Warn("reconnect after a timed disconnect", "error", err.Error())
		return false
	}
	return true
}

// SetPinned implements panel.App: pinned devices come first in the panel
// and in the tray's copy menu (F-159). Only devices of the current network
// document can be pinned; unpinning always works, also for a removed one.
func (r *Runtime) SetPinned(name string, pinned bool) error {
	if pinned {
		store, err := member.Open(r.path(DeviceDir))
		if err != nil {
			return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
		}
		if _, ok := store.Document().DeviceByName(name); !ok {
			return errors.New("bu adla bir cihaz yok")
		}
	}
	return r.updateSettings(func(st *settings) (bool, error) {
		i := slices.Index(st.Pinned, name)
		switch {
		case pinned && i >= 0, !pinned && i < 0:
			return false, nil
		case pinned:
			if len(st.Pinned) >= maxPinned {
				return false, errors.New("en fazla 64 cihaz sabitlenebilir")
			}
			st.Pinned = append(st.Pinned, name)
		default:
			st.Pinned = slices.Delete(st.Pinned, i, i+1)
		}
		return true, nil
	})
}

// sortPinned moves the pinned peers to the front, keeping the order of the
// document within each group, and marks them.
func sortPinned(peers []panel.PeerInfo, pinned []string) {
	for i := range peers {
		peers[i].Pinned = slices.Contains(pinned, peers[i].Name)
	}
	slices.SortStableFunc(peers, func(a, b panel.PeerInfo) int {
		switch {
		case a.Pinned && !b.Pinned:
			return -1
		case !a.Pinned && b.Pinned:
			return 1
		}
		return 0
	})
}
