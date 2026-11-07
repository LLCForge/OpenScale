package node

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/sysinfo"
)

// Detailed inventory transfer (ADR-0143). The base system report announces
// the inventory's version and identifier; an admin device fetches the
// gzip-compressed inventory in ChunkSize pieces with "infod" messages on
// InfoPort (or the control port for the coordinator's own), and fetches
// it again only when the identifier changes.

// detailCache keeps fetched inventories by peer. Entries are checked
// against the identifier the peer announces, so engines of one process
// can share it.
var detailCache = sysinfo.NewDetailCache(1024)

const (
	// detailBudget chunk requests per admin per detailWindow: a full
	// inventory is at most MaxDetailBlob/ChunkSize+1 (24) chunks.
	detailBudget = 64
	detailWindow = 10 * time.Second
	maxChunks    = sysinfo.MaxDetailBlob/control.ChunkSize + 1
)

var detailLimit struct {
	mu sync.Mutex
	m  map[netip.Addr]*detailWindowState
}

type detailWindowState struct {
	start time.Time
	n     int
}

// allowDetail rate-limits chunk requests per admin address. Chunks are
// served from memory; the limit only bounds the reply traffic.
func allowDetail(src netip.Addr, now time.Time) bool {
	detailLimit.mu.Lock()
	defer detailLimit.mu.Unlock()
	if detailLimit.m == nil || len(detailLimit.m) > 1024 {
		detailLimit.m = map[netip.Addr]*detailWindowState{}
	}
	w := detailLimit.m[src]
	if w == nil || now.Sub(w.start) > detailWindow || now.Before(w.start) {
		w = &detailWindowState{start: now}
		detailLimit.m[src] = w
	}
	w.n++
	return w.n <= detailBudget
}

// serveInfoDetail answers one inventory chunk request from an admin
// device, like serveInfo answers the base report.
func (e *Engine) serveInfoDetail(in packet.Info, req control.Message) bool {
	now := e.cfg.Now()
	e.mu.Lock()
	self := e.self.IPv4
	allowed := e.admins[in.Src]
	e.mu.Unlock()
	if in.Dst != self || !allowed {
		return false
	}
	if e.peerAddrRefused(in.Src) {
		return true // quarantine and lost mode, exitdns_g3.go
	}
	if !allowDetail(in.Src, now) {
		return true
	}
	resp := detailChunkReply(req)
	resp.ID = req.ID
	out, err := control.Encode(resp)
	if err != nil {
		return true
	}
	reply, err := packet.BuildUDP4(self, in.Src, control.InfoPort, in.SrcPort, out)
	if err == nil {
		e.wrap.Inject(reply)
	}
	return true
}

// detailChunkReply builds the answer to an inventory chunk request from
// this process's own inventory (the coordinator does the same).
func detailChunkReply(req control.Message) control.Message {
	data, total, id, ok := sysinfo.DetailChunk(req.Digest, req.Offset, control.ChunkSize)
	if !ok {
		return control.Message{T: control.TypeError, Error: "inventory unavailable"}
	}
	off := req.Offset
	if id != req.Digest {
		off = 0 // the announced snapshot is gone; the newest starts over
	}
	return control.Message{T: control.TypeInfoDetail, Offset: off, Total: total, Digest: id, Data: data}
}

type detailCall func(context.Context, control.Message) (control.Message, error)

// attachDetail fills in.Detail from the cache or by fetching it. A failed
// fetch keeps the last inventory known for the peer (possibly older) so
// the panel does not flicker; the base report is never failed by it.
func (e *Engine) attachDetail(ctx context.Context, in *sysinfo.Info, key string, call detailCall) {
	if in.DetailVer != sysinfo.DetailVersion || in.DetailID == "" {
		return
	}
	cached, same := detailCache.Get(key, in.DetailID)
	if same {
		in.Detail = cached
		return
	}
	d, id, err := fetchDetail(ctx, in.DetailID, call)
	if err != nil {
		in.Detail = cached
		return
	}
	detailCache.Put(key, id, d, e.cfg.Now())
	in.Detail, in.DetailID = d, id
}

// fetchDetail reassembles one inventory. When the peer's inventory changed
// since its report, the reply names the new identifier and the fetch
// starts over once.
func fetchDetail(ctx context.Context, id string, call detailCall) (*sysinfo.Detail, string, error) {
	for range 2 {
		var blob []byte
		total, changed := -1, false
		for range maxChunks + 1 {
			resp, err := call(ctx, control.Message{T: control.TypeInfoDetail, Digest: id, Offset: len(blob)})
			if err != nil {
				return nil, "", err
			}
			if resp.T != control.TypeInfoDetail {
				return nil, "", errors.New("unexpected inventory reply")
			}
			if resp.Digest != id {
				if !sysinfo.ValidDetailID(resp.Digest) {
					return nil, "", errors.New("bad inventory identifier")
				}
				id, changed = resp.Digest, true
				break
			}
			if resp.Offset != len(blob) || resp.Total <= 0 || resp.Total > sysinfo.MaxDetailBlob ||
				(total >= 0 && resp.Total != total) || len(resp.Data) == 0 || len(blob)+len(resp.Data) > resp.Total {
				return nil, "", errors.New("inconsistent inventory chunk")
			}
			total = resp.Total
			blob = append(blob, resp.Data...)
			if len(blob) == total {
				d, err := sysinfo.DecodeDetail(blob, id)
				return d, id, err
			}
		}
		if !changed {
			return nil, "", errors.New("inventory longer than announced")
		}
	}
	return nil, "", errors.New("inventory keeps changing")
}
