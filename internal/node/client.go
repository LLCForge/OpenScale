package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
)

const (
	callTimeout = 2 * time.Second
	callRetries = 3
	// clientPort is the source port of control requests inside the tunnel.
	clientPort = 40404
)

// ErrNoReply is returned when the coordinator did not answer.
var ErrNoReply = errors.New("coordinator did not reply")

// client sends control requests through the tunnel and matches replies.
type client struct {
	mu      sync.Mutex
	self    netip.Addr
	coord   netip.Addr
	inject  func([]byte) bool
	pending map[uint32]chan control.Message
	// onPush receives messages the coordinator pushes to PushPort
	// (ADR-0025, ADR-0026); nil drops them.
	onPush func(control.Message)
	// coords are the overlay addresses of every usable coordinator
	// (ADR-0111); their replies, pushes and relayed packets are taken too.
	coords map[netip.Addr]bool
}

func newClient(inject func([]byte) bool) *client {
	return &client{inject: inject, pending: map[uint32]chan control.Message{}}
}

func (c *client) setAddrs(self, coord netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.self, c.coord = self, coord
}

// intercept consumes packets from the coordinator. Control replies are
// delivered to waiting calls; any other packet from the coordinator is
// dropped, because the coordinator never legitimately sends anything else.
func (c *client) intercept(pkt []byte) bool {
	info, err := packet.Parse(pkt)
	if err != nil {
		return false
	}
	c.mu.Lock()
	coord, self := c.coord, c.self
	fromCoord := coord.IsValid() && info.Src == coord || c.coords[info.Src]
	c.mu.Unlock()
	isReply := info.Proto == packet.ProtoUDP && !info.Fragment && info.Dst == self && info.DstPort == clientPort
	switch {
	case fromCoord:
		if isReply && info.SrcPort == control.Port {
			if msg, err := control.Decode(info.Payload); err == nil {
				c.deliver(msg)
			}
		}
		isPush := info.Proto == packet.ProtoUDP && !info.Fragment && info.Dst == self &&
			info.DstPort == control.PushPort && info.SrcPort == control.Port
		if isPush && c.onPush != nil {
			if msg, err := control.Decode(info.Payload); err == nil {
				c.onPush(msg)
			}
		}
		return true
	case isReply && (info.SrcPort == control.InfoPort || info.SrcPort == control.GossipPort):
		// A device answering this admin's status query. Unsolicited
		// packets find no pending id and are dropped.
		if msg, err := control.Decode(info.Payload); err == nil {
			c.deliver(msg)
		}
		return true
	}
	return false
}

func (c *client) deliver(msg control.Message) {
	c.mu.Lock()
	ch, ok := c.pending[msg.ID]
	c.mu.Unlock()
	if ok {
		select {
		case ch <- msg:
		default:
		}
	}
}

// call sends req to the coordinator and waits for the reply.
func (c *client) call(ctx context.Context, req control.Message) (control.Message, error) {
	c.mu.Lock()
	coord := c.coord
	c.mu.Unlock()
	return c.callTo(ctx, coord, control.Port, req)
}

// callTo sends req to dst:port inside the tunnel and waits for the reply,
// retrying on timeout.
func (c *client) callTo(ctx context.Context, dst netip.Addr, port uint16, req control.Message) (control.Message, error) {
	var idBuf [4]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return control.Message{}, err
	}
	req.ID = binary.BigEndian.Uint32(idBuf[:])
	payload, err := control.Encode(req)
	if err != nil {
		return control.Message{}, err
	}
	ch := make(chan control.Message, 1)
	c.mu.Lock()
	self := c.self
	c.pending[req.ID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
	}()
	if !self.IsValid() || !dst.IsValid() {
		return control.Message{}, errors.New("no coordinator configured")
	}
	pkt, err := packet.BuildUDP4(self, dst, clientPort, port, payload)
	if err != nil {
		return control.Message{}, err
	}
	for attempt := 0; attempt < callRetries; attempt++ {
		c.inject(pkt)
		timer := time.NewTimer(callTimeout)
		select {
		case msg := <-ch:
			timer.Stop()
			if msg.T == control.TypeError {
				return msg, errors.New("coordinator: " + msg.Error)
			}
			return msg, nil
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return control.Message{}, ctx.Err()
		}
	}
	return control.Message{}, ErrNoReply
}
