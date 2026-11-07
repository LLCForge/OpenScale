package service

import (
	"bufio"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/version"
)

// Local metrics (F-198, #186) in the Prometheus text format 0.0.4. The
// endpoint is off by default and, when on, answers only on loopback with
// the app token and the caller check (ADR-0050, ADR-0105). The values are
// totals for the whole tunnel: no per-peer series, no addresses.

type metricWriter struct {
	w    *bufio.Writer
	seen map[string]bool
}

func (m *metricWriter) head(name, typ, help string) {
	if m.seen[name] {
		return
	}
	m.seen[name] = true
	fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m *metricWriter) value(name, typ, help string, v float64, labels ...string) {
	m.head(name, typ, help)
	m.w.WriteString(name)
	if len(labels) > 0 {
		m.w.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				m.w.WriteByte(',')
			}
			fmt.Fprintf(m.w, "%s=%q", labels[i], escapeLabel(labels[i+1]))
		}
		m.w.WriteByte('}')
	}
	fmt.Fprintf(m.w, " %v\n", v)
}

// escapeLabel keeps label values on one line; %q escapes quotes and
// backslashes.
func escapeLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// WriteMetrics implements panel.Observability.
func (o *Observer) WriteMetrics(w io.Writer) error {
	if !o.metricsOn() {
		return panel.ErrMetricsOff
	}
	return o.writeMetrics(w)
}

func (o *Observer) writeMetrics(w io.Writer) error {
	m := &metricWriter{w: bufio.NewWriter(w), seen: map[string]bool{}}
	m.value("openscale_build_info", "gauge", "OpenScale version.", 1, "version", version.Version)
	m.value("openscale_process_start_time_seconds", "gauge", "When the observed tunnel process started (Unix time).", float64(o.start.Unix()))

	diag := &EngineDiag{Engine: o.cfg.Engine, Interface: o.cfg.Interface, Now: o.cfg.Now}
	st, _ := diag.BaseStatus()
	m.value("openscale_tunnel_up", "gauge", "1 while the tunnel runs.", b2f(st.Running))
	if st.Running {
		m.value("openscale_document_version", "gauge", "Version of the network document in use.", float64(st.DocumentVersion))
		if st.LastSync != nil {
			m.value("openscale_last_sync_timestamp_seconds", "gauge", "Last successful contact with the coordinator (Unix time).", float64(st.LastSync.Unix()))
		}
		m.value("openscale_sync_error", "gauge", "1 while the coordinator cannot be reached or refused the last document.", b2f(st.LastSyncError != ""))
		online, paths := 0, map[string]int{panel.PathDirect: 0, panel.PathRelay: 0, panel.PathNone: 0}
		var rx, tx uint64
		for _, p := range st.Peers {
			if p.Online {
				online++
			}
			paths[p.Path]++
			rx += p.RxBytes
			tx += p.TxBytes
		}
		m.value("openscale_peers", "gauge", "Devices this one has a tunnel to, by state.", float64(online), "state", "online")
		m.value("openscale_peers", "gauge", "", float64(len(st.Peers)-online), "state", "offline")
		keys := make([]string, 0, len(paths))
		for k := range paths {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.value("openscale_peer_paths", "gauge", "Peers by path: direct, relay or none.", float64(paths[k]), "path", k)
		}
		m.value("openscale_wireguard_received_bytes_total", "counter", "Bytes received from all peers.", float64(rx))
		m.value("openscale_wireguard_sent_bytes_total", "counter", "Bytes sent to all peers.", float64(tx))
		if e := o.cfg.Engine(); e != nil {
			f := e.PacketFilter()
			fs := f.Stats()
			m.value("openscale_filter_packets_total", "counter", "Packets seen by the packet filter.", float64(fs.PassedIn), "direction", "in", "verdict", "pass")
			m.value("openscale_filter_packets_total", "counter", "", float64(fs.DeniedIn), "direction", "in", "verdict", "deny")
			m.value("openscale_filter_packets_total", "counter", "", float64(fs.PassedOut), "direction", "out", "verdict", "pass")
			m.value("openscale_filter_packets_total", "counter", "", float64(fs.DeniedOut), "direction", "out", "verdict", "deny")
			m.value("openscale_filter_bytes_total", "counter", "Bytes the packet filter passed.", float64(fs.BytesIn), "direction", "in")
			m.value("openscale_filter_bytes_total", "counter", "", float64(fs.BytesOut), "direction", "out")
			m.value("openscale_filter_flows", "gauge", "Tracked connections.", float64(fs.Flows))
			tot := f.DenyLog().Totals()
			reasons := make([]string, 0, len(tot))
			for k := range tot {
				reasons = append(reasons, k)
			}
			sort.Strings(reasons)
			for _, k := range reasons {
				m.value("openscale_filter_denied_total", "counter", "Refused packets by reason.", float64(tot[k]), "reason", k)
			}
		}
	}
	m.value("openscale_events_total", "counter", "Events published on the local event stream.", float64(o.bus.Seq()))

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.value("go_goroutines", "gauge", "Number of goroutines.", float64(runtime.NumGoroutine()))
	m.value("go_memstats_heap_alloc_bytes", "gauge", "Heap bytes allocated and in use.", float64(ms.HeapAlloc))
	m.value("go_memstats_sys_bytes", "gauge", "Bytes obtained from the system.", float64(ms.Sys))
	m.value("go_gc_cycles_total", "counter", "Completed GC cycles.", float64(ms.NumGC))
	return m.w.Flush()
}
