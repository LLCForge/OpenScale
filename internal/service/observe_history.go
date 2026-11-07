package service

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/usagehist"
)

// Local histories (#505, #516): hourly byte totals per device for 30 days
// and OpenScale's own processor, memory and battery cost over the last
// day. Only totals are kept, in the owner-only state directory; nothing
// is sent anywhere.

const (
	// trafficHistoryFile keeps the hourly totals across restarts.
	trafficHistoryFile = "traffic-history.json"
	// trafficEvery is how often the per-device counters are read.
	trafficEvery = time.Minute
	// historySaveEvery bounds how often the history is written.
	historySaveEvery = 10 * time.Minute
)

// historyState is the Observer's histories.
type historyState struct {
	once      sync.Once
	traffic   *usagehist.Traffic
	res       *usagehist.Resources
	mu        sync.Mutex
	lastRead  time.Time
	lastRes   time.Time
	lastSave  time.Time
	saveError string
}

var _ panel.UsageHistory = (*Observer)(nil)

// histories returns the histories, loading the saved one on first use.
func (o *Observer) histories() *historyState {
	h := &o.hist
	h.once.Do(func() {
		h.res = usagehist.NewResources(usagehist.SystemProbe())
		h.traffic = usagehist.NewTraffic()
		if o.cfg.Dir == "" {
			return
		}
		data, err := securefile.ReadPrivate(filepath.Join(o.cfg.Dir, trafficHistoryFile), usagehist.MaxFileSize)
		switch {
		case err == nil:
			if t, derr := usagehist.DecodeTraffic(data, o.cfg.Now()); derr == nil {
				h.traffic = t
			} else {
				o.cfg.Logger.Warn("traffic history unreadable; starting a new one", "error", derr.Error())
			}
		case !errors.Is(err, fs.ErrNotExist):
			o.cfg.Logger.Warn("traffic history unreadable", "error", err.Error())
		}
	})
	return h
}

// sampleHistories is called from Run; it reads the counters at most once
// a minute and samples the resources every usagehist.SampleEvery.
func (o *Observer) sampleHistories(now time.Time) {
	h := o.histories()
	h.mu.Lock()
	readTraffic := now.Sub(h.lastRead) >= trafficEvery
	readRes := now.Sub(h.lastRes) >= usagehist.SampleEvery || h.lastRes.IsZero()
	if readTraffic {
		h.lastRead = now
	}
	if readRes {
		h.lastRes = now
	}
	h.mu.Unlock()
	if readRes {
		h.res.Sample(now)
	}
	if !readTraffic {
		return
	}
	diag := &EngineDiag{Engine: o.cfg.Engine, Interface: o.cfg.Interface, Now: o.cfg.Now}
	st, err := diag.BaseStatus()
	if err != nil || !st.Running {
		return
	}
	present := make(map[string]bool, len(st.Peers))
	for _, p := range st.Peers {
		present[p.Name] = true
		h.traffic.Observe(p.Name, p.RxBytes, p.TxBytes, now)
	}
	h.traffic.Forget(func(d string) bool { return present[d] })
	o.saveHistory(now, false)
}

// saveHistory writes the traffic history when it changed, at most every
// historySaveEvery unless force.
func (o *Observer) saveHistory(now time.Time, force bool) {
	h := o.histories()
	if o.cfg.Dir == "" || !h.traffic.Dirty() {
		return
	}
	h.mu.Lock()
	due := force || now.Sub(h.lastSave) >= historySaveEvery
	if due {
		h.lastSave = now
	}
	h.mu.Unlock()
	if !due {
		return
	}
	data, err := h.traffic.Encode()
	if err == nil {
		err = securefile.Replace(filepath.Join(o.cfg.Dir, trafficHistoryFile), data)
	}
	h.mu.Lock()
	h.saveError = ""
	if err != nil {
		h.saveError = err.Error()
	}
	h.mu.Unlock()
	if err != nil {
		o.cfg.Logger.Warn("traffic history not saved", "error", err.Error())
	}
}

// TrafficHistory implements panel.UsageHistory.
func (o *Observer) TrafficHistory(device string, hours int) (panel.TrafficHistoryReply, error) {
	h := o.histories()
	now := o.cfg.Now()
	rep := panel.TrafficHistoryReply{Schema: panel.DiagSchema, Hours: hours, Device: device, Devices: []panel.TrafficDeviceTotal{}}
	for _, d := range h.traffic.Devices() {
		rx, tx := h.traffic.Total(d, hours, now)
		rep.Devices = append(rep.Devices, panel.TrafficDeviceTotal{Name: d, Rx: rx, Tx: tx})
	}
	if device != "" {
		rep.Points = h.traffic.Series(device, hours, now)
	}
	return rep, nil
}

// ResourceUsage implements panel.UsageHistory.
func (o *Observer) ResourceUsage() panel.ResourceReply {
	h := o.histories()
	samples := h.res.Samples()
	if samples == nil {
		samples = []usagehist.Sample{}
	}
	return panel.ResourceReply{
		Schema:             panel.DiagSchema,
		SampleEverySeconds: int(usagehist.SampleEvery / time.Second),
		Summary:            h.res.Summarize(),
		Samples:            samples,
	}
}
