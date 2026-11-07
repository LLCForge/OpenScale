package filter

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Flow tap of the intrusion detector (#729, ADR-0221).
//
// The tunnel's packet filter is where every packet gets its verdict. The
// tap samples, at that point and from the headers only, each new
// connection attempt: a TCP SYN without ACK, or the first UDP packet of a
// flow the tap has not seen recently. It writes the source and
// destination address, the destination port, the protocol and whether
// the filter refused the packet into a fixed ring; the detector drains
// the ring on its own goroutine. Payload bytes are never read.
//
// The writer side takes no lock and allocates nothing: one atomic add
// reserves a slot and the record is published with a sequence number
// (a per-slot seqlock), so the reader never blocks the tunnel. A full
// ring overwrites the oldest records and counts them as lost: the tunnel
// always wins over the detector. With no tap installed the filter pays
// one atomic pointer load per packet.

// Default ring and dedup sizes; both are powers of two.
const (
	DefaultTapSlots = 4096
	tapSeenSlots    = 8192
	// tapSeenMask indexes the UDP first-packet dedup table.
	tapSeenMask = tapSeenSlots - 1
)

// Record flag bits.
const (
	tapDropped = 1 << iota
	tapInbound
	tapV6
)

// flowTapPtr keeps filter.go free of the atomic import.
type flowTapPtr = atomic.Pointer[FlowTap]

// TapRecord is one sampled connection attempt.
type TapRecord struct {
	Src, Dst netip.Addr
	Proto    uint8
	Port     uint16
	// Dropped is true when the filter refused the packet.
	Dropped bool
	// Inbound is true for packets arriving from the tunnel.
	Inbound bool
}

type tapSlot struct {
	seq atomic.Uint64
	// w holds src (2 words), dst (2 words) and meta (port, proto, flags).
	w [5]atomic.Uint64
}

// FlowTap is the lock-free sampler ring. Writers are the filter's
// packet paths (any number, concurrently); there is one reader.
type FlowTap struct {
	head  atomic.Uint64
	slots []tapSlot
	mask  uint64
	seen  []atomic.Uint64
	lost  atomic.Uint64

	rmu  sync.Mutex // serialises readers
	tail uint64
}

// NewFlowTap returns a tap with room for slots records, rounded up to a
// power of two (DefaultTapSlots when slots <= 0, at most 1<<20).
func NewFlowTap(slots int) *FlowTap {
	if slots <= 0 {
		slots = DefaultTapSlots
	}
	slots = min(slots, 1<<20)
	n := 1
	for n < slots {
		n <<= 1
	}
	return &FlowTap{slots: make([]tapSlot, n), mask: uint64(n - 1), seen: make([]atomic.Uint64, tapSeenSlots)}
}

// SetFlowTap installs t as the filter's tap; nil removes it.
func (f *Filter) SetFlowTap(t *FlowTap) { f.tap.Store(t) }

// FlowTap returns the installed tap or nil.
func (f *Filter) FlowTap() *FlowTap { return f.tap.Load() }

// tapFlow offers one decided packet to the tap. It runs outside f.mu.
func (f *Filter) tapFlow(pkt []byte, inbound, ok bool) {
	t := f.tap.Load()
	if t == nil {
		return
	}
	t.sample(pkt, inbound, !ok)
}

// sample reads the IP and transport headers and records a connection
// attempt; anything else returns at once.
func (t *FlowTap) sample(pkt []byte, inbound, dropped bool) {
	if len(pkt) < 20 {
		return
	}
	var (
		proto      uint8
		l4         int
		hi1, lo1   uint64
		hi2, lo2   uint64
		flags      uint64
		srcPortKey uint64
	)
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		// Later fragments carry no transport header.
		if ihl < 20 || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return
		}
		proto, l4 = pkt[9], ihl
		lo1 = uint64(binary.BigEndian.Uint32(pkt[12:16]))
		lo2 = uint64(binary.BigEndian.Uint32(pkt[16:20]))
	case 6:
		if len(pkt) < 40 {
			return
		}
		// Extension headers are not walked: the filter already refuses
		// what it cannot parse, and the detector needs only the common case.
		proto, l4 = pkt[6], 40
		hi1, lo1 = binary.BigEndian.Uint64(pkt[8:16]), binary.BigEndian.Uint64(pkt[16:24])
		hi2, lo2 = binary.BigEndian.Uint64(pkt[24:32]), binary.BigEndian.Uint64(pkt[32:40])
		flags |= tapV6
	default:
		return
	}
	var port uint16
	switch proto {
	case 6: // TCP: a SYN without ACK opens a connection.
		if len(pkt) < l4+14 || pkt[l4+13]&0x12 != 0x02 {
			return
		}
		port = binary.BigEndian.Uint16(pkt[l4+2 : l4+4])
	case 17: // UDP: the first packet of a flow the tap has not seen lately.
		if len(pkt) < l4+8 {
			return
		}
		port = binary.BigEndian.Uint16(pkt[l4+2 : l4+4])
		srcPortKey = uint64(binary.BigEndian.Uint16(pkt[l4 : l4+2]))
		h := tapHash(hi1, lo1, hi2, lo2, srcPortKey<<16|uint64(port)) | 1
		s := &t.seen[h&tapSeenMask]
		if s.Load() == h {
			return
		}
		s.Store(h)
	default:
		return
	}
	if dropped {
		flags |= tapDropped
	}
	if inbound {
		flags |= tapInbound
	}
	pos := t.head.Add(1) - 1
	s := &t.slots[pos&t.mask]
	s.seq.Store(0) // writing
	s.w[0].Store(hi1)
	s.w[1].Store(lo1)
	s.w[2].Store(hi2)
	s.w[3].Store(lo2)
	s.w[4].Store(uint64(port)<<16 | uint64(proto)<<8 | flags)
	s.seq.Store(pos + 1)
}

// tapHash mixes the flow key (splitmix64 steps); collisions only make
// the tap sample a UDP flow twice or skip one.
func tapHash(a, b, c, d, e uint64) uint64 {
	h := uint64(0x9e3779b97f4a7c15)
	for _, v := range [...]uint64{a, b, c, d, e} {
		h ^= v
		h *= 0xbf58476d1ce4e5b9
		h ^= h >> 31
	}
	return h
}

// Drain hands up to limit records (all when limit <= 0) to fn, oldest first,
// and returns how many it handed. Records overwritten before they were
// read are counted in Lost.
func (t *FlowTap) Drain(limit int, fn func(TapRecord)) int {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	size := t.mask + 1
	h := t.head.Load()
	if h-t.tail > size {
		t.lost.Add(h - size - t.tail)
		t.tail = h - size
	}
	n := 0
	for t.tail < h && (limit <= 0 || n < limit) {
		s := &t.slots[t.tail&t.mask]
		want := t.tail + 1
		q1 := s.seq.Load()
		if q1 == 0 || q1 < want {
			// The writer has not published yet; try again next time.
			break
		}
		if q1 > want {
			t.lost.Add(1)
			t.tail++
			continue
		}
		var w [5]uint64
		for i := range w {
			w[i] = s.w[i].Load()
		}
		if s.seq.Load() != q1 {
			t.lost.Add(1)
			t.tail++
			continue
		}
		t.tail++
		fn(decodeTap(w))
		n++
	}
	return n
}

// Lost is the number of records overwritten before they were read.
func (t *FlowTap) Lost() uint64 { return t.lost.Load() }

func decodeTap(w [5]uint64) TapRecord {
	meta := w[4]
	flags := meta & 0xff
	r := TapRecord{
		Proto:   uint8(meta >> 8),
		Port:    uint16(meta >> 16),
		Dropped: flags&tapDropped != 0,
		Inbound: flags&tapInbound != 0,
	}
	if flags&tapV6 != 0 {
		var a, b [16]byte
		binary.BigEndian.PutUint64(a[:8], w[0])
		binary.BigEndian.PutUint64(a[8:], w[1])
		binary.BigEndian.PutUint64(b[:8], w[2])
		binary.BigEndian.PutUint64(b[8:], w[3])
		r.Src, r.Dst = netip.AddrFrom16(a), netip.AddrFrom16(b)
		return r
	}
	var a, b [4]byte
	binary.BigEndian.PutUint32(a[:], uint32(w[1]))
	binary.BigEndian.PutUint32(b[:], uint32(w[3]))
	r.Src, r.Dst = netip.AddrFrom4(a), netip.AddrFrom4(b)
	return r
}
