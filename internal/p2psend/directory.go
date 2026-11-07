package p2psend

import (
	"net/netip"
	"sync"
	"time"
)

// Peer is a member device as the signed document lists it.
type Peer struct {
	Name string
	Key  Key
	Addr netip.Addr
}

// Directory answers who a key or a tunnel address belongs to. The node
// builds it from the verified signed document; the coordinator is never
// asked.
type Directory interface {
	ByKey(Key) (Peer, bool)
	ByAddr(netip.Addr) (Peer, bool)
}

// StaticDirectory is an in-memory Directory.
type StaticDirectory struct {
	mu     sync.RWMutex
	byKey  map[Key]Peer
	byAddr map[netip.Addr]Peer
}

// NewStaticDirectory returns a directory of peers.
func NewStaticDirectory(peers ...Peer) *StaticDirectory {
	d := &StaticDirectory{byKey: map[Key]Peer{}, byAddr: map[netip.Addr]Peer{}}
	for _, p := range peers {
		d.Add(p)
	}
	return d
}

// Add inserts or replaces a peer.
func (d *StaticDirectory) Add(p Peer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.byKey[p.Key] = p
	if p.Addr.IsValid() {
		d.byAddr[p.Addr.Unmap()] = p
	}
}

// ByKey implements Directory.
func (d *StaticDirectory) ByKey(k Key) (Peer, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.byKey[k]
	return p, ok
}

// ByAddr implements Directory.
func (d *StaticDirectory) ByAddr(a netip.Addr) (Peer, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.byAddr[a.Unmap()]
	return p, ok
}

// DeviceRecord is the part of a signed document device entry the
// directory needs. The node fills it from trust.Document.Devices (Name,
// WireGuardKey, IPv4, IPv6, ExpiresAt); keeping the trust package out of
// this one keeps the file format code independent of the document.
type DeviceRecord struct {
	Name      string
	WireGuard [KeySize]byte
	IPv4      netip.Addr
	IPv6      netip.Addr
	ExpiresAt time.Time
}

// DirectoryFromDevices lists the unexpired devices. Revoked devices are
// not in the document's device list, so they are never found.
func DirectoryFromDevices(devs []DeviceRecord, now time.Time) *StaticDirectory {
	d := NewStaticDirectory()
	for _, dev := range devs {
		if !dev.ExpiresAt.IsZero() && !now.Before(dev.ExpiresAt) {
			continue
		}
		k := Key(dev.WireGuard)
		if k.IsZero() {
			continue
		}
		p := Peer{Name: dev.Name, Key: k, Addr: dev.IPv4}
		d.Add(p)
		if dev.IPv6.IsValid() {
			d.mu.Lock()
			d.byAddr[dev.IPv6.Unmap()] = p
			d.mu.Unlock()
		}
	}
	return d
}
