package node

import "os"

// Priority queues of the TUN wrapper (ADR-0043, #142). Without a classifier
// every packet from the OS goes to fromOS and Read behaves as before.

// queueFor returns the queue a packet from the OS goes to.
func (w *wrapTUN) queueFor(pkt []byte) chan []byte {
	if w.classify == nil {
		return w.fromOS
	}
	switch w.classify(pkt) {
	case prioHigh:
		return w.fromOSHigh
	case prioLow:
		return w.fromOSLow
	default:
		return w.fromOS
	}
}

// next returns the next packet for WireGuard: control packets first, then,
// with priority on, interactive, normal and bulk packets in that order.
func (w *wrapTUN) next() ([]byte, error) {
	if w.classify == nil {
		select {
		case pkt := <-w.inject:
			return pkt, nil
		case pkt := <-w.fromOS:
			return pkt, nil
		case <-w.closed:
			return nil, os.ErrClosed
		}
	}
	select {
	case pkt := <-w.inject:
		return pkt, nil
	default:
	}
	select {
	case pkt := <-w.fromOSHigh:
		return pkt, nil
	default:
	}
	select {
	case pkt := <-w.fromOS:
		return pkt, nil
	default:
	}
	select {
	case pkt := <-w.inject:
		return pkt, nil
	case pkt := <-w.fromOSHigh:
		return pkt, nil
	case pkt := <-w.fromOS:
		return pkt, nil
	case pkt := <-w.fromOSLow:
		return pkt, nil
	case <-w.closed:
		return nil, os.ErrClosed
	}
}
