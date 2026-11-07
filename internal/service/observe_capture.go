package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// Debug packet capture (F-197, #193) and profiling (F-201). Both run only
// on the owner's request through the loopback API, are bounded in time and
// size, and write only to the caller's connection: the command line saves
// the file on the owner's own computer. Neither is ever sent anywhere.

// linkTypeRaw is LINKTYPE_RAW: packets start with the IPv4 or IPv6 header.
const linkTypeRaw = 101

func writePcapHeader(w io.Writer, snap int) error {
	var h [24]byte
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], uint32(snap))
	binary.LittleEndian.PutUint32(h[20:], linkTypeRaw)
	_, err := w.Write(h[:])
	return err
}

func writePcapRecord(w io.Writer, p filter.CapturedPacket) (int, error) {
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:], uint32(p.At.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(p.At.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(p.Data)))
	binary.LittleEndian.PutUint32(h[12:], uint32(p.Length))
	if _, err := w.Write(h[:]); err != nil {
		return 0, err
	}
	_, err := w.Write(p.Data)
	return len(h) + len(p.Data), err
}

// captureOptions turns the request into filter options.
func captureOptions(doc *trust.Document, req panel.CaptureRequest) (filter.CaptureOptions, string, error) {
	o := filter.CaptureOptions{Denied: req.Denied, Port: uint16(req.Port), Snap: req.Snap}
	who := "tüm cihazlar"
	if req.Peer != "" {
		if doc == nil {
			return o, "", ErrTunnelNotRunning
		}
		d, ok := FindDevice(doc, req.Peer)
		if !ok {
			return o, "", fmt.Errorf("%q ağ belgesinde yok", req.Peer)
		}
		who = d.Name
		for _, a := range []netip.Addr{d.IPv4, d.IPv6} {
			if a.IsValid() {
				o.Addrs = append(o.Addrs, a)
			}
		}
	}
	switch req.Proto {
	case "":
	case "tcp":
		o.Proto = packet.ProtoTCP
	case "udp":
		o.Proto = packet.ProtoUDP
	case "icmp":
		o.Proto = packet.ProtoICMPv4
	default:
		n, err := strconv.Atoi(req.Proto)
		if err != nil || n < 0 || n > 255 {
			return o, "", fmt.Errorf("protokol %q geçersiz", req.Proto)
		}
		o.Proto = uint8(n)
	}
	switch req.Direction {
	case "in":
		o.Inbound = true
	case "out":
		o.Outbound = true
	}
	return o, who, nil
}

// Capture implements panel.Observability.
func (o *Observer) Capture(ctx context.Context, req panel.CaptureRequest, w io.Writer) (panel.CaptureSummary, error) {
	var sum panel.CaptureSummary
	e := o.cfg.Engine()
	if e == nil {
		return sum, ErrTunnelNotRunning
	}
	opts, who, err := captureOptions(e.Document(), req)
	if err != nil {
		return sum, err
	}
	c, err := e.PacketFilter().StartCapture(opts)
	if err != nil {
		return sum, err
	}
	defer c.Stop()
	snap := opts.Snap
	if snap <= 0 {
		snap = filter.DefaultSnap
	}
	content := "yalnızca başlıklar"
	if snap > filter.DefaultSnap {
		content = fmt.Sprintf("paket başına %d bayta kadar içerik", snap)
	}
	o.Security("packet_capture", audit.SeverityWarning, panel.CategorySecurity, "",
		fmt.Sprintf("Tünel içi paket yakalama başladı: %s, %d sn, en çok %d bayt, %s.", who, req.Seconds, req.MaxBytes, content), false)
	cw := &countWriter{w: w}
	if err := writePcapHeader(cw, snap); err != nil {
		return sum, err
	}
	timer := time.NewTimer(time.Duration(req.Seconds) * time.Second)
	defer timer.Stop()
	for cw.n < req.MaxBytes {
		select {
		case <-ctx.Done():
			sum.Dropped, sum.Bytes = c.Dropped(), cw.n
			return sum, nil
		case <-timer.C:
			sum.Dropped, sum.Bytes = c.Dropped(), cw.n
			return sum, nil
		case p := <-c.Packets():
			if cw.n+16+int64(len(p.Data)) > req.MaxBytes {
				sum.Dropped, sum.Bytes = c.Dropped()+1, cw.n
				return sum, nil
			}
			if _, err := writePcapRecord(cw, p); err != nil {
				sum.Dropped, sum.Bytes = c.Dropped(), cw.n
				return sum, err
			}
			sum.Packets++
		}
	}
	sum.Dropped, sum.Bytes = c.Dropped(), cw.n
	return sum, nil
}

// Profile implements panel.Observability (F-201). It uses runtime/pprof
// directly; net/http/pprof is never registered on any server.
func (o *Observer) Profile(ctx context.Context, req panel.ProfileRequest, w io.Writer) error {
	if !o.profilingOn() {
		return panel.ErrProfilingOff
	}
	if req.Kind == "cpu" {
		if err := pprof.StartCPUProfile(w); err != nil {
			return fmt.Errorf("CPU profili başlatılamadı (başka bir profil sürüyor olabilir): %w", err)
		}
		t := time.NewTimer(time.Duration(req.Seconds) * time.Second)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		t.Stop()
		pprof.StopCPUProfile()
	} else {
		p := pprof.Lookup(req.Kind)
		if p == nil {
			return fmt.Errorf("profil %q yok", req.Kind)
		}
		if err := p.WriteTo(w, req.Debug); err != nil {
			return err
		}
	}
	o.Security("profile_taken", audit.SeverityInfo, panel.CategorySecurity, "", "Yerel "+req.Kind+" profili alındı.", false)
	return nil
}
