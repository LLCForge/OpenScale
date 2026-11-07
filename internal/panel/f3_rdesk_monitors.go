package panel

import (
	"slices"
	"strconv"
	"sync"

	"github.com/openscale/openscale/internal/rdesk"
	"golang.org/x/net/websocket"
)

// Monitor picker and the "all monitors" view in the panel's remote desktop
// viewer (#120). The connect request may name the first monitor
// ("primary", "all" or a number); the "ready" message and a "monitors"
// message after every change list the target's monitors, and the page
// switches with {"type": "monitor", "index": n} (-1 for all of them).
// Switching only changes what is captured, so view sessions may do it
// too. A second administrator device that finds the screen controlled is
// told "control_busy" and can join as a viewer (#853).

// rdeskMonitorView is one monitor for the page.
type rdeskMonitorView struct {
	Index   int  `json:"index"`
	Width   int  `json:"width"`
	Height  int  `json:"height"`
	X       int  `json:"x"`
	Y       int  `json:"y"`
	Primary bool `json:"primary"`
}

// rdeskMonitorOption reads the connect request's monitor ("" is the
// primary one).
func rdeskMonitorOption(s string) (int, bool) {
	switch s {
	case "", "primary":
		return rdesk.MonitorPrimary, true
	case "all":
		return rdesk.MonitorAll, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 15 || strconv.Itoa(n) != s {
		return 0, false
	}
	return n, true
}

func rdeskMonitorList(ms []rdesk.Monitor) []rdeskMonitorView {
	out := make([]rdeskMonitorView, 0, len(ms))
	for i, m := range ms {
		out = append(out, rdeskMonitorView{Index: i, Width: m.Bounds.Dx(), Height: m.Bounds.Dy(), X: m.Bounds.Min.X, Y: m.Bounds.Min.Y, Primary: m.Primary})
	}
	return out
}

// rdeskMonitorState remembers what the page was last told.
type rdeskMonitorState struct {
	monitors []rdesk.Monitor
	selected int
	sent     bool
}

// rdeskMonitorsMessage is the "monitors" message for the client's current
// list and selection; changed is false when the page already has it.
func (st *rdeskMonitorState) message(c *rdesk.Client) (rdeskMessage, bool) {
	ms := c.Monitors()
	sel := c.Desktop().Monitor
	if st.sent && sel == st.selected && slices.Equal(ms, st.monitors) {
		return rdeskMessage{}, false
	}
	st.monitors, st.selected, st.sent = ms, sel, true
	return rdeskMessage{Type: "monitors", Monitors: rdeskMonitorList(ms), Selected: &sel}, true
}

// notifyMonitors sends the list after a frame when it changed.
func (st *rdeskMonitorState) notify(ws *websocket.Conn, mu *sync.Mutex, c *rdesk.Client) {
	if m, changed := st.message(c); changed {
		_ = sendRDesk(ws, mu, m)
	}
}

// rdeskViewerCommand handles the page messages any session may send;
// it reports whether m was one of them.
func rdeskViewerCommand(v *rdeskViewer, m rdeskMessage) bool {
	if m.Type != "monitor" {
		return false
	}
	if m.Index == rdesk.MonitorAll || (m.Index >= 0 && m.Index < len(v.client.Monitors())) {
		_ = v.client.SelectMonitor(m.Index)
	}
	return true
}
