package rdesk

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"image"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Viewer side of protocol version 3 (ADR-0146): session quality figures
// (#436), annotations (#425) and the file browser (#435).

const (
	statsInterval = time.Second
	maxEchoRTT    = 2 * time.Minute
)

// Stats are the session's quality figures for the viewer's overlay (#436).
type Stats struct {
	// FPS is the complete frames per second received over the last
	// interval.
	FPS float64
	// RTT is the smoothed round trip of the echo messages, including
	// queueing behind frames; 0 when unknown (a version 2 server).
	RTT time.Duration
	// BytesPerSec is the received data rate over the last interval.
	BytesPerSec float64
	// Width, Height and Scale describe the current image.
	Width, Height, Scale int
	// Frames and Bytes are totals since the session opened.
	Frames uint64
	Bytes  uint64
	// Version is the protocol version the device accepted.
	Version int
}

type opResult struct {
	l   listing
	err error
}

type fileOpState struct {
	id      uint32
	list    bool
	res     chan opResult
	w       io.Writer
	limit   uint64
	written uint64
	h       hash.Hash
}

type clientV3 struct {
	rxBytes atomic.Uint64
	base    time.Time

	mu         sync.Mutex
	rtt        time.Duration
	fps        float64
	bw         float64
	lastAt     time.Time
	lastFrames uint64
	lastBytes  uint64

	opMu   sync.Mutex // one file operation at a time
	nextID atomic.Uint32
	pmu    sync.Mutex
	op     *fileOpState
}

func (v *clientV3) init() {
	v.base = time.Now()
	v.lastAt = v.base
}

// Extended reports whether the device speaks protocol version 3.
func (c *Client) Extended() bool { return c.version >= ProtocolVersionExt }

// Stats returns the current quality figures.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	st := Stats{Width: c.desktop.Width, Height: c.desktop.Height, Scale: c.desktop.Scale, Frames: c.frames, Version: int(c.version)}
	c.mu.Unlock()
	st.Bytes = c.v3.rxBytes.Load()
	c.v3.mu.Lock()
	st.FPS, st.RTT, st.BytesPerSec = c.v3.fps, c.v3.rtt, c.v3.bw
	c.v3.mu.Unlock()
	return st
}

// statsLoop measures the rates once per interval and, on version 3, sends
// an echo for the round trip.
func (c *Client) statsLoop() {
	defer c.wg.Done()
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		if c.Extended() {
			if c.write(encodeEcho(msgEcho, uint64(time.Since(c.v3.base)))) != nil {
				return
			}
		}
		now := time.Now()
		c.mu.Lock()
		frames := c.frames
		c.mu.Unlock()
		bytes := c.v3.rxBytes.Load()
		c.v3.mu.Lock()
		if dt := now.Sub(c.v3.lastAt).Seconds(); dt > 0 {
			c.v3.fps = float64(frames-c.v3.lastFrames) / dt
			c.v3.bw = float64(bytes-c.v3.lastBytes) / dt
		}
		c.v3.lastAt, c.v3.lastFrames, c.v3.lastBytes = now, frames, bytes
		c.v3.mu.Unlock()
	}
}

func (c *Client) handleV3(t msgType, p []byte) error {
	switch t {
	case msgEchoReply:
		v, err := decodeEcho(p)
		if err != nil {
			return err
		}
		rtt := time.Since(c.v3.base) - time.Duration(v)
		if rtt < 0 || rtt > maxEchoRTT {
			// Not an echo this client sent.
			return nil
		}
		c.v3.mu.Lock()
		if c.v3.rtt == 0 {
			c.v3.rtt = rtt
		} else {
			c.v3.rtt = (7*c.v3.rtt + rtt) / 8
		}
		c.v3.mu.Unlock()
		return nil
	case msgFileListing:
		l, err := decodeListing(p)
		if err != nil {
			return err
		}
		return c.v3.with(l.id, true, func(*fileOpState) (opResult, bool) { return opResult{l: l}, true })
	case msgFileChunk:
		id, off, data, err := decodeChunk(p)
		if err != nil {
			return err
		}
		var perr error
		err = c.v3.with(id, false, func(op *fileOpState) (opResult, bool) {
			if off != op.written {
				perr = fmt.Errorf("%w: dosya parçası sırası bozuk", ErrProtocol)
				return opResult{err: perr}, true
			}
			if op.written+uint64(len(data)) > op.limit {
				_ = c.write(encodeMsg(msgFileCancel, cancelPayload(id)))
				return opResult{err: ErrFileTooLarge}, true
			}
			if _, werr := op.w.Write(data); werr != nil {
				_ = c.write(encodeMsg(msgFileCancel, cancelPayload(id)))
				return opResult{err: fmt.Errorf("%w: yerel yazma: %w", ErrFileFailed, werr)}, true
			}
			op.h.Write(data)
			op.written += uint64(len(data))
			return opResult{}, false
		})
		return errors.Join(err, perr)
	case msgFileDone:
		f, err := decodeFileDone(p)
		if err != nil {
			return err
		}
		return c.v3.with(f.id, false, func(op *fileOpState) (opResult, bool) {
			res := opResult{err: fileStatusError(f.status, f.reason)}
			if res.err == nil {
				var sum [sha256.Size]byte
				copy(sum[:], op.h.Sum(nil))
				if f.size != op.written || sum != f.sum {
					res.err = fmt.Errorf("%w: boyut veya özet tutmuyor", ErrFileFailed)
				}
			}
			return res, true
		})
	}
	return fmt.Errorf("%w: bilinmeyen ileti %#x", ErrProtocol, uint8(t))
}

func cancelPayload(id uint32) []byte {
	return []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)}
}

// with runs fn on the pending operation for id under the lock, so a
// waiter that gave up never races with it; fn reports whether the
// operation ended. A message for an operation that was cancelled or has
// ended is ignored; one for an id never used is a protocol error.
func (v *clientV3) with(id uint32, list bool, fn func(*fileOpState) (opResult, bool)) error {
	v.pmu.Lock()
	defer v.pmu.Unlock()
	op := v.op
	if op == nil || op.id != id {
		if id == 0 || id > v.nextID.Load() {
			return fmt.Errorf("%w: beklenmeyen dosya yanıtı", ErrProtocol)
		}
		return nil
	}
	if op.list != list {
		return ErrProtocol
	}
	r, done := fn(op)
	if done {
		v.op = nil
		select {
		case op.res <- r:
		default:
		}
	}
	return nil
}

func (v *clientV3) finish(op *fileOpState, r opResult) {
	v.pmu.Lock()
	if v.op == op {
		v.op = nil
	}
	v.pmu.Unlock()
	select {
	case op.res <- r:
	default:
	}
}

// abort ends a pending operation when the session fails.
func (v *clientV3) abort(err error) {
	v.pmu.Lock()
	op := v.op
	v.op = nil
	v.pmu.Unlock()
	if op != nil {
		select {
		case op.res <- opResult{err: err}:
		default:
		}
	}
}

// fileRequest sends one request and waits for its result.
func (c *Client) fileRequest(ctx context.Context, t msgType, path string, op *fileOpState) (listing, error) {
	if !c.Extended() {
		return listing{}, ErrFeatureUnsupported
	}
	if c.opts.Mode != ModeControl {
		return listing{}, ErrFileDenied
	}
	if len(path) > maxBrowsePath {
		return listing{}, errors.New("rdesk: yol çok uzun")
	}
	if _, _, ok := splitBrowsePath(path); !ok {
		return listing{}, errors.New("rdesk: geçersiz yol (kök/alt/klasör biçiminde, '..' olmadan)")
	}
	c.v3.opMu.Lock()
	defer c.v3.opMu.Unlock()
	op.id = c.v3.nextID.Add(1)
	op.res = make(chan opResult, 1)
	c.v3.pmu.Lock()
	c.v3.op = op
	c.v3.pmu.Unlock()
	if err := c.write(encodeFileReq(t, op.id, path)); err != nil {
		c.v3.finish(op, opResult{err: err})
		return listing{}, err
	}
	select {
	case r := <-op.res:
		return r.l, r.err
	case <-c.done:
		c.v3.finish(op, opResult{})
		return listing{}, c.Err()
	case <-ctx.Done():
		c.v3.finish(op, opResult{})
		_ = c.write(encodeMsg(msgFileCancel, cancelPayload(op.id)))
		return listing{}, ctx.Err()
	}
}

// ListFiles lists a folder on the device (#435). "" lists the folders the
// owner chose; "root/sub/dir" lists inside one. It needs a control session,
// a files rule from this device and a version 3 device. truncated is set
// when the folder has more than 2000 entries.
func (c *Client) ListFiles(ctx context.Context, path string) (entries []FileEntry, truncated bool, err error) {
	l, err := c.fileRequest(ctx, msgFileList, path, &fileOpState{list: true})
	if err != nil {
		return nil, false, err
	}
	if err := fileStatusError(l.status, l.reason); err != nil {
		return nil, false, err
	}
	return l.entries, l.truncated, nil
}

// FetchFile copies the file at path ("root/sub/file") from the device into
// w and returns its size. The device sends the size and SHA-256 at the end
// and both are checked; limit (at most MaxFetchBytes, 0 for that) bounds
// the size. On an error w may hold part of the file.
func (c *Client) FetchFile(ctx context.Context, path string, w io.Writer, limit int64) (int64, error) {
	if limit <= 0 || limit > MaxFetchBytes {
		limit = MaxFetchBytes
	}
	op := &fileOpState{w: w, limit: uint64(limit), h: sha256.New()}
	if _, err := c.fileRequest(ctx, msgFileGet, path, op); err != nil {
		return int64(op.written), err
	}
	return int64(op.written), nil
}

// Annotate draws a mark on the device's screen (#425): an arrow at one
// point, a stroke through 2 to 64 points, or AnnotateClear. Points are
// image pixels as in SendPointer; color indexes AnnotationColors. View
// sessions may annotate too; no input reaches the device.
func (c *Client) Annotate(kind AnnotationKind, color uint8, points []image.Point) error {
	if !c.Extended() {
		return ErrFeatureUnsupported
	}
	if !validAnnotation(kind, color, len(points)) {
		return errors.New("rdesk: geçersiz işaret")
	}
	for _, p := range points {
		if p.X < 0 || p.Y < 0 || p.X >= maxDim || p.Y >= maxDim {
			return errors.New("rdesk: işaret noktası görüntünün dışında")
		}
	}
	return c.write(annotationMsg{kind: kind, color: color, points: points}.encode())
}
