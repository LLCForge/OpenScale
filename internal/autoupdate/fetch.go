package autoupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/rollout"
)

// Fetcher sends release requests to the coordinator inside the tunnel
// (node.Engine.ReleaseCall).
type Fetcher interface {
	ReleaseCall(ctx context.Context, req control.Message) (control.Message, error)
}

// Errors of the mirror protocol.
var (
	// ErrNotServed: the coordinator does not know the release requests (an
	// older coordinator) or serves no mirror.
	ErrNotServed = errors.New("koordinatör sürüm dağıtmıyor")
	// ErrReleaseChanged: the owner published again during the download.
	ErrReleaseChanged = errors.New("koordinatördeki sürüm indirme sırasında değişti")
	// ErrFileMissing: the mirror has no such file.
	ErrFileMissing = errors.New("koordinatörde bu dosya yok")
)

// announcement is a TypeRelease reply.
type announcement struct {
	Version, Manifest, Digest string
	Size                      int
	// Source and Checked: the coordinator's upstream source, if any.
	Source  string
	Checked time.Time
	// Rollout is the coordinator's ring progress (ADR-0235); nil when it
	// sent none.
	Rollout *rollout.Announcement
}

// announce asks for the announcement; report is this device's rollout
// report, sent in the request's Data (an older coordinator ignores it).
func announce(ctx context.Context, f Fetcher, report []byte) (announcement, error) {
	resp, err := f.ReleaseCall(ctx, control.Message{T: control.TypeRelease, Data: report})
	if err != nil {
		if strings.Contains(err.Error(), "unknown message type") {
			return announcement{}, ErrNotServed
		}
		return announcement{}, err
	}
	a := announcement{Version: resp.Release, Manifest: resp.File, Digest: resp.Digest, Size: resp.Size, Source: resp.Source, Rollout: decodeRollout(resp.Data)}
	if resp.Checked > 0 {
		a.Checked = time.Unix(resp.Checked, 0).UTC()
	}
	if a.Version == "" {
		return a, nil
	}
	if !control.ValidReleaseFileName(a.Manifest) || len(a.Digest) != 64 || a.Size <= 0 {
		return announcement{}, errors.New("koordinatörün sürüm ilanı geçersiz")
	}
	return a, nil
}

// pace bounds the request rate below the coordinator's per-device control
// limit (DefaultControlRate) so a download never starves this device's own
// control traffic.
type pace struct {
	every time.Duration
	mu    sync.Mutex
	next  time.Time
}

func (p *pace) wait(ctx context.Context) error {
	if p.every <= 0 {
		return ctx.Err()
	}
	p.mu.Lock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	p.next = at.Add(p.every)
	p.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// download fetches name of the publication digest into w. It returns the
// file size, refusing anything larger than limit (or, with exact > 0, any
// other size).
func download(ctx context.Context, f Fetcher, digest, name string, limit, exact int64, parallel int, rate int, w io.WriterAt) (int64, error) {
	if parallel < 1 {
		parallel = 1
	}
	p := &pace{}
	if rate > 0 {
		p.every = time.Second / time.Duration(rate)
	}
	get := func(ctx context.Context, off int) (control.Message, error) {
		if err := p.wait(ctx); err != nil {
			return control.Message{}, err
		}
		resp, err := f.ReleaseCall(ctx, control.Message{T: control.TypeReleaseFile, File: name, Digest: digest, Offset: off})
		if err != nil {
			switch {
			case strings.Contains(err.Error(), "release changed"), strings.Contains(err.Error(), "no release"):
				return resp, ErrReleaseChanged
			case strings.Contains(err.Error(), "not found"):
				return resp, ErrFileMissing
			}
			return resp, err
		}
		if resp.File != name || resp.Digest != digest || resp.Offset != off {
			return resp, errors.New("koordinatör beklenmeyen bir parça gönderdi")
		}
		return resp, nil
	}
	first, err := get(ctx, 0)
	if err != nil {
		return 0, err
	}
	total := int64(first.Total)
	switch {
	case total <= 0 || total > limit:
		return 0, fmt.Errorf("%s boyutu (%d) sınırın dışında", name, total)
	case exact > 0 && total != exact:
		return 0, fmt.Errorf("%s boyutu (%d) manifestodakiyle (%d) aynı değil", name, total, exact)
	}
	check := func(resp control.Message, off int64) error {
		want := min(int64(control.ChunkSize), total-off)
		if int64(resp.Total) != total || int64(len(resp.Data)) != want {
			return errors.New("koordinatör tutarsız bir parça gönderdi")
		}
		_, err := w.WriteAt(resp.Data, off)
		return err
	}
	if err := check(first, 0); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	offsets := make(chan int64)
	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		cancel()
	}
	for range parallel {
		wg.Go(func() {
			for off := range offsets {
				resp, err := get(ctx, int(off))
				if err == nil {
					err = check(resp, off)
				}
				if err != nil {
					fail(err)
					return
				}
			}
		})
	}
feed:
	for off := int64(control.ChunkSize); off < total; off += control.ChunkSize {
		select {
		case offsets <- off:
		case <-ctx.Done():
			break feed
		}
	}
	close(offsets)
	wg.Wait()
	if firstErr != nil {
		return 0, firstErr
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return total, nil
}
