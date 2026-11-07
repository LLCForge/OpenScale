package node

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Traffic shaping (ADR-0043): padding (#36), cover traffic (#37) and
// interactive priority (#142). All three are off by default; padding and
// cover traffic cost bandwidth and battery, which CoverTrafficCost and
// PaddingCost put into numbers for the settings screen.

// PaddingMode chooses how packets are padded before encryption.
type PaddingMode int

const (
	// PaddingOff leaves packets as they are (WireGuard pads to 16 bytes).
	PaddingOff PaddingMode = iota
	// PaddingBuckets pads to 128, 256, 512 or 1024 bytes, or the MTU.
	PaddingBuckets
	// PaddingMTU pads every packet to the MTU.
	PaddingMTU
)

func (m PaddingMode) String() string {
	switch m {
	case PaddingOff:
		return "kapalı"
	case PaddingBuckets:
		return "kovalar"
	case PaddingMTU:
		return "MTU"
	default:
		return fmt.Sprintf("bilinmeyen(%d)", int(m))
	}
}

// Cover traffic bounds, in bytes per second inside the tunnel.
const (
	MinCoverTraffic = 256
	MaxCoverTraffic = 64 << 10
	// coverPort is the discard port packets are sent to on the
	// coordinator, whose control interface drops them (only 4040 and 4042
	// are handled there).
	coverPort = 9
	// wireOverhead is what each tunnel packet adds on the wire: WireGuard
	// data header and tag (32), UDP (8) and IPv4 (20).
	wireOverhead = 60
	// coverMinWait and coverMaxWait clamp one interval.
	coverMinWait = 5 * time.Millisecond
	coverMaxWait = 10 * time.Minute
)

// paddingBuckets are the sizes of PaddingBuckets below the MTU.
var paddingBuckets = []int{128, 256, 512, 1024}

// paddedSize is the size a packet of n bytes is padded to.
func paddedSize(mode PaddingMode, n, mtu int) int {
	if n <= 0 || n >= mtu {
		return n
	}
	switch mode {
	case PaddingMTU:
		return mtu
	case PaddingBuckets:
		for _, b := range paddingBuckets {
			if n <= b && b <= mtu {
				return b
			}
		}
		return mtu
	}
	return n
}

// padder returns the function the TUN wrapper pads packets with, or nil.
// The padding is zeros after the IP packet; the receiving WireGuard cuts
// the packet to the length in its IP header, so peers of any version
// ignore it.
func (e *Engine) padder() func(buf []byte, n int) int {
	if e.cfg.Padding == PaddingOff {
		return nil
	}
	mode, mtu := e.cfg.Padding, e.cfg.MTU
	return func(buf []byte, n int) int {
		t := min(paddedSize(mode, n, mtu), len(buf))
		if t <= n {
			return n
		}
		clear(buf[n:t]) // never send what an earlier packet left in buf
		e.extras.padded.Add(1)
		e.extras.padBytes.Add(uint64(t - n))
		return t
	}
}

// imix is the simple IMIX packet size mix (7:4:1) used for estimates.
var imix = []struct{ size, weight int }{{40, 7}, {576, 4}, {1500, 1}}

// PaddingCost estimates the extra bandwidth padding costs, in percent of
// the unpadded traffic, for a simple IMIX mix (sizes capped at the MTU).
func PaddingCost(mode PaddingMode, mtu int) (float64, error) {
	if err := ValidateMTU(mtu); err != nil {
		return 0, err
	}
	var orig, padded float64
	for _, p := range imix {
		s := min(p.size, mtu)
		orig += float64(s * p.weight)
		padded += float64(paddedSize(mode, s, mtu) * p.weight)
	}
	return (padded - orig) / orig * 100, nil
}

// CoverEstimate is what cover traffic costs.
type CoverEstimate struct {
	// BytesPerSecond is the configured rate inside the tunnel.
	BytesPerSecond int
	// AveragePacket is the mean cover packet size inside the tunnel.
	AveragePacket int
	// PacketsPerHour is also the most radio wake-ups per hour it causes
	// on a phone (battery cost).
	PacketsPerHour int64
	// WireBytesPerHour, WireBytesPerDay and WireBytesPer30Days include the
	// WireGuard, UDP and IP headers.
	WireBytesPerHour   int64
	WireBytesPerDay    int64
	WireBytesPer30Days int64
}

// coverSizes are the sizes cover packets are drawn from.
func coverSizes(mtu int) []int {
	var out []int
	for _, b := range paddingBuckets {
		if b < mtu {
			out = append(out, b)
		}
	}
	return append(out, mtu)
}

// CoverTrafficCost estimates the cost of cover traffic at rate bytes per
// second with the given MTU.
func CoverTrafficCost(rate, mtu int) (CoverEstimate, error) {
	if rate < MinCoverTraffic || rate > MaxCoverTraffic {
		return CoverEstimate{}, fmt.Errorf("sahte trafik hızı %d ile %d B/sn arasında olmalı", MinCoverTraffic, MaxCoverTraffic)
	}
	if err := ValidateMTU(mtu); err != nil {
		return CoverEstimate{}, err
	}
	sizes := coverSizes(mtu)
	sum := 0
	for _, s := range sizes {
		sum += s
	}
	avg := sum / len(sizes)
	perHour := int64(rate) * 3600 / int64(avg)
	wireHour := int64(rate)*3600 + perHour*wireOverhead
	return CoverEstimate{BytesPerSecond: rate, AveragePacket: avg, PacketsPerHour: perHour,
		WireBytesPerHour: wireHour, WireBytesPerDay: wireHour * 24, WireBytesPer30Days: wireHour * 24 * 30}, nil
}

// TrafficShapingStats are measured while the engine runs.
type TrafficShapingStats struct {
	Padding       PaddingMode
	PaddedPackets uint64
	PaddingBytes  uint64
	// CoverRate is the configured cover traffic rate (0 off).
	CoverRate    int
	CoverPackets uint64
	CoverBytes   uint64
	// InteractivePriority reports whether priority queues are on.
	InteractivePriority bool
}

// TrafficShaping returns the measured padding and cover traffic.
func (e *Engine) TrafficShaping() TrafficShapingStats {
	return TrafficShapingStats{Padding: e.cfg.Padding, PaddedPackets: e.extras.padded.Load(), PaddingBytes: e.extras.padBytes.Load(),
		CoverRate: e.cfg.CoverTraffic, CoverPackets: e.extras.coverPkts.Load(), CoverBytes: e.extras.coverBytes.Load(),
		InteractivePriority: e.cfg.InteractivePriority}
}

// newCoverRand returns a generator seeded from crypto/rand: the timing and
// sizes of cover packets must not be predictable.
func newCoverRand() (*mrand.Rand, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return mrand.New(mrand.NewChaCha8(seed)), nil
}

// coverPacket builds one cover packet of size bytes from self to the
// coordinator's discard port.
func coverPacket(self, coord trust.Device, size int, r *mrand.Rand) ([]byte, error) {
	const headers = 28 // IPv4 + UDP
	if size < headers {
		size = headers
	}
	if !self.IPv4.IsValid() || !coord.IPv4.IsValid() {
		return nil, errors.New("adres yok")
	}
	src := uint16(49152 + r.IntN(65536-49152))
	return packet.BuildUDP4(self.IPv4, coord.IPv4, src, coverPort, make([]byte, size-headers))
}

// runCover sends cover packets to the coordinator at about
// CoverTraffic bytes per second with exponentially distributed gaps
// (a Poisson process), until ctx ends.
func (e *Engine) runCover(ctx context.Context) {
	r, err := newCoverRand()
	if err != nil {
		e.logger.Warn("cover traffic", "error", err.Error())
		return
	}
	sizes := coverSizes(e.cfg.MTU)
	rate := float64(e.cfg.CoverTraffic)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		size := sizes[r.IntN(len(sizes))]
		wait := time.Duration(r.ExpFloat64() * float64(size) / rate * float64(time.Second))
		timer.Reset(min(max(wait, coverMinWait), coverMaxWait))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		doc := e.cfg.Store.Document()
		if doc.Coordinator == nil || e.wrap == nil {
			continue
		}
		self, err := e.Self()
		if err != nil {
			continue
		}
		pkt, err := coverPacket(self, trust.Device{IPv4: doc.Coordinator.IPv4}, size, r)
		if err != nil {
			continue
		}
		if e.wrap.Inject(pkt) {
			e.extras.coverPkts.Add(1)
			e.extras.coverBytes.Add(uint64(len(pkt)))
		}
	}
}

// Packet priority classes for InteractivePriority.
const (
	prioNormal = iota
	prioHigh
	prioLow
)

// classifyPacket sorts a packet by flow: ICMP and interactive services
// high, file sending and speed tests low, the rest normal. The ports of
// both ends count, so replies are sorted like requests.
func classifyPacket(pkt []byte) int {
	info, err := packet.Parse(pkt)
	if err != nil {
		return prioNormal
	}
	switch info.Proto {
	case packet.ProtoICMPv4, packet.ProtoICMPv6:
		return prioHigh
	case packet.ProtoTCP, packet.ProtoUDP:
	default:
		return prioNormal
	}
	if info.Fragment {
		return prioNormal
	}
	low := false
	for _, p := range [2]uint16{info.SrcPort, info.DstPort} {
		switch p {
		case 22, 53, 3389, 5900, trust.SSHPort, trust.RemoteDesktopPort, control.Port, control.InfoPort, control.RelayPort, control.PQPort:
			return prioHigh
		case trust.FilesPort, trust.SpeedtestPort:
			low = true
		}
	}
	if low {
		return prioLow
	}
	return prioNormal
}

// classifier returns the classification function for the TUN wrapper, or
// nil when priority is off.
func (e *Engine) classifier() func(pkt []byte) int {
	if !e.cfg.InteractivePriority {
		return nil
	}
	return classifyPacket
}
