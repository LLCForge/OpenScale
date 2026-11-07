package coordinator

import (
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
)

const (
	tunMTU      = 1420
	outQueueLen = 2048
)

// handlerFunc answers one control datagram; nil means no reply.
type handlerFunc func(src netip.Addr, payload []byte) []byte

// controlTUN is a userspace stand-in for a network interface. WireGuard
// hands it decrypted packets from peers; it answers control datagrams sent
// to the coordinator's address and drops everything else, so no traffic is
// ever forwarded between devices and no OS interface or privilege is needed.
type controlTUN struct {
	addr   netip.Addr
	handle handlerFunc
	// relay forwards a relay datagram; nil disables relaying.
	relay   func(src netip.Addr, payload []byte) (netip.Addr, []byte, bool)
	out     chan []byte
	events  chan tun.Event
	closed  chan struct{}
	closeMu sync.Once
}

func newControlTUN(addr netip.Addr, handle handlerFunc) *controlTUN {
	t := &controlTUN{
		addr:   addr,
		handle: handle,
		out:    make(chan []byte, outQueueLen),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *controlTUN) File() *os.File { return nil }

func (t *controlTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.out:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *controlTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if offset > len(buf) {
			continue
		}
		info, err := packet.Parse(buf[offset:])
		if err != nil || info.Fragment || info.Proto != packet.ProtoUDP || info.Dst != t.addr {
			continue
		}
		if info.DstPort == control.RelayPort && info.SrcPort == control.RelayPort && t.relay != nil {
			dst, out, ok := t.relay(info.Src, info.Payload)
			if !ok {
				continue
			}
			pkt, err := packet.BuildUDP4(t.addr, dst, control.RelayPort, control.RelayPort, out)
			if err != nil {
				continue
			}
			select {
			case t.out <- pkt:
			default:
				// Queue full: drop; WireGuard and TCP above it recover.
			}
			continue
		}
		if info.DstPort != control.Port {
			continue
		}
		reply := t.handle(info.Src, info.Payload)
		if reply == nil {
			continue
		}
		pkt, err := packet.BuildUDP4(t.addr, info.Src, control.Port, info.SrcPort, reply)
		if err != nil {
			continue
		}
		select {
		case t.out <- pkt:
		default:
			// Queue full: drop the reply; the client retries.
		}
	}
	return len(bufs), nil
}

func (t *controlTUN) MTU() (int, error)        { return tunMTU, nil }
func (t *controlTUN) Name() (string, error)    { return "openscale-coordinator", nil }
func (t *controlTUN) Events() <-chan tun.Event { return t.events }
func (t *controlTUN) BatchSize() int           { return 1 }

func (t *controlTUN) Close() error {
	t.closeMu.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
