package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

// The tray follows the service's event stream (F-182, ADR-0105) with long
// polls instead of only asking for the status every few seconds, and shows
// desktop notifications for the events the service marks (F-158, #191):
// a device added, removed or revoked, the kill switch blocking traffic and
// refused documents. The owner turns them off with "openscale notify off"
// or in the panel.

const (
	// eventWait is one long poll's wait; the HTTP timeout leaves room.
	eventWait    = 25 * time.Second
	eventTimeout = eventWait + 15*time.Second
	// eventRetry is the pause after a failed poll (service restarting).
	eventRetry = 5 * time.Second
	// slowRefreshTicks: while the stream works, the status is still read
	// every this many ticks (5 s each) as a safety net.
	slowRefreshTicks = 6
)

// pollEvents asks for the events after since, waiting up to wait.
func (c *trayClient) pollEvents(ctx context.Context, hc *http.Client, since uint64, wait time.Duration) (panel.EventStreamReply, error) {
	var rep panel.EventStreamReply
	url := c.apiBase() + panel.LocalAPIPrefix + "/events/poll?since=" + strconv.FormatUint(since, 10) +
		"&wait=" + strconv.Itoa(int(wait/time.Second))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return rep, err
	}
	if err := c.authorize(req); err != nil {
		return rep, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return rep, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rep, fmt.Errorf("servis yanıtı: %s", resp.Status)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxReplySize*4)).Decode(&rep)
	return rep, err
}

// notificationsFor returns the texts to announce from one answer.
func notificationsFor(rep panel.EventStreamReply) []string {
	if !rep.Notifications {
		return nil
	}
	var out []string
	for _, ev := range rep.Events {
		if ev.Notify && ev.Message != "" {
			out = append(out, ev.Message)
		}
	}
	return out
}

// refreshGate thins out the periodic status refresh while the event
// stream works.
type refreshGate struct {
	streamUp atomic.Bool
	ticks    atomic.Int32
}

// skip reports whether this tick's refresh can be left out.
func (g *refreshGate) skip() bool {
	if !g.streamUp.Load() {
		return false
	}
	if g.ticks.Add(1) >= slowRefreshTicks {
		g.ticks.Store(0)
		return false
	}
	return true
}

// followEvents runs until ctx ends. onEvents gets the notification texts
// of each answer that carried events; events that happened before the
// tray started are not announced.
func followEvents(ctx context.Context, c *trayClient, gate *refreshGate, onEvents func(notes []string)) {
	hc := &http.Client{Timeout: eventTimeout, CheckRedirect: c.http.CheckRedirect, Transport: c.http.Transport}
	var since uint64
	primed := false
	for ctx.Err() == nil {
		wait := eventWait
		if !primed {
			wait = 0
		}
		rep, err := c.pollEvents(ctx, hc, since, wait)
		if err != nil {
			gate.streamUp.Store(false)
			primed = false
			if errors.Is(err, context.Canceled) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(eventRetry):
			}
			continue
		}
		gate.streamUp.Store(true)
		if rep.Next < since {
			// The service restarted: its numbering began again.
			primed = false
		}
		since = rep.Next
		if !primed {
			primed = true
			continue
		}
		if len(rep.Events) > 0 {
			onEvents(notificationsFor(rep))
		}
	}
}
