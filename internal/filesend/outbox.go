package filesend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Waiting for an offline recipient (#140, ADR-0104). The file stays on
// the sender: the outbox only remembers the path, size and digest, and the
// sender retries while the recipient is unreachable. Nothing is stored on
// the coordinator or any other device. A file that changes while waiting
// is not sent (the recipient would get something the owner never chose).

const (
	defaultOutboxMaxAge = 7 * 24 * time.Hour
	maxOutboxItems      = 1000
	outboxMinBackoff    = time.Minute
	outboxMaxBackoff    = time.Hour
	maxOutboxFile       = 1 << 20
)

// ErrFileChanged means a queued file changed or disappeared before it
// could be sent.
var ErrFileChanged = errors.New("bekleyen dosya değişti veya silindi; gönderilmedi")

// ErrExpired means the recipient did not come online in time.
var ErrExpired = errors.New("alıcı bekleme süresi içinde çevrimiçi olmadı")

// OutboxItem is one file waiting for its recipient.
type OutboxItem struct {
	ID        string       `json:"id"`
	Peer      string       `json:"peer"`
	Path      string       `json:"path"`
	Name      string       `json:"name"`
	Size      int64        `json:"size"`
	SHA256    string       `json:"sha256"`
	Metadata  MetadataMode `json:"metadata,omitempty"`
	Queued    time.Time    `json:"queued"`
	Attempts  int          `json:"attempts,omitempty"`
	NextTry   time.Time    `json:"next_try"`
	LastError string       `json:"last_error,omitempty"`
}

// OutboxConfig configures an Outbox.
type OutboxConfig struct {
	// File stores the queue (owner-only).
	File string
	// MaxAge drops items whose recipient stayed offline this long
	// (default 7 days).
	MaxAge time.Duration
	// Resolve returns the recipient's file service address when it is
	// reachable now; false keeps the item waiting without counting an
	// attempt.
	Resolve func(peer string) (netip.AddrPort, bool)
	// OnDone, if set, reports items that were sent (nil error) or dropped.
	OnDone func(OutboxItem, SendResult, error)
	// Now returns the current time (tests).
	Now func() time.Time
}

// Outbox is a persistent queue of files for offline recipients.
type Outbox struct {
	cfg   OutboxConfig
	mu    sync.Mutex
	items []OutboxItem
	run   sync.Mutex
}

// OpenOutbox loads the queue file, creating an empty queue when missing.
func OpenOutbox(cfg OutboxConfig) (*Outbox, error) {
	if cfg.File == "" || cfg.Resolve == nil {
		return nil, errors.New("filesend: kuyruk dosyası ve Resolve zorunlu")
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaultOutboxMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	o := &Outbox{cfg: cfg}
	data, err := securefile.ReadPrivate(cfg.File, maxOutboxFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("filesend: kuyruk okunamadı: %w", err)
	default:
		if err := json.Unmarshal(data, &o.items); err != nil {
			return nil, fmt.Errorf("filesend: kuyruk dosyası bozuk: %w", err)
		}
	}
	return o, nil
}

func (o *Outbox) saveLocked() error {
	data, err := json.Marshal(o.items)
	if err != nil {
		return err
	}
	return securefile.Replace(o.cfg.File, data)
}

// Enqueue adds a file for peer. The file must be a regular file; its
// digest is taken now and checked again before sending.
func (o *Outbox) Enqueue(peer, path, name string, mode MetadataMode) (OutboxItem, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return OutboxItem{}, err
	}
	if name == "" {
		name = filepath.Base(abs)
	}
	if _, err := SanitizeName(name); err != nil {
		return OutboxItem{}, err
	}
	size, sum, err := digestPath(abs)
	if err != nil {
		return OutboxItem{}, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return OutboxItem{}, err
	}
	now := o.cfg.Now()
	it := OutboxItem{ID: hex.EncodeToString(id[:]), Peer: peer, Path: abs, Name: name, Size: size, SHA256: sum, Metadata: mode, Queued: now, NextTry: now}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.items) >= maxOutboxItems {
		return OutboxItem{}, errors.New("filesend: bekleyen dosya kuyruğu dolu")
	}
	o.items = append(o.items, it)
	if err := o.saveLocked(); err != nil {
		o.items = o.items[:len(o.items)-1]
		return OutboxItem{}, err
	}
	return it, nil
}

func digestPath(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	if !fi.Mode().IsRegular() {
		return 0, "", errors.New("yalnızca normal dosyalar gönderilebilir")
	}
	sum, err := fileDigest(f)
	return fi.Size(), sum, err
}

// Items returns a copy of the queue.
func (o *Outbox) Items() []OutboxItem {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.items)
}

// Remove cancels a waiting item.
func (o *Outbox) Remove(id string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	i := slices.IndexFunc(o.items, func(it OutboxItem) bool { return it.ID == id })
	if i < 0 {
		return false, nil
	}
	o.items = slices.Delete(o.items, i, i+1)
	return true, o.saveLocked()
}

// permanent reports errors that retrying cannot fix.
func permanent(err error) bool {
	return errors.Is(err, ErrRejected) || errors.Is(err, ErrTooLarge) || errors.Is(err, ErrBadName) ||
		errors.Is(err, ErrFileChanged) || errors.Is(err, ErrMetadataUnsupported) || errors.Is(err, ErrProtocol)
}

// RunOnce tries every due item whose recipient is reachable and returns
// how many were sent.
func (o *Outbox) RunOnce(ctx context.Context) int {
	o.run.Lock()
	defer o.run.Unlock()
	now := o.cfg.Now()
	sent := 0
	for _, it := range o.Items() {
		if ctx.Err() != nil {
			break
		}
		if now.Sub(it.Queued) > o.cfg.MaxAge {
			o.finish(it, SendResult{}, ErrExpired)
			continue
		}
		if now.Before(it.NextTry) {
			continue
		}
		addr, ok := o.cfg.Resolve(it.Peer)
		if !ok {
			continue
		}
		res, err := o.sendItem(ctx, addr, it)
		switch {
		case err == nil:
			sent++
			o.finish(it, res, nil)
		case ctx.Err() != nil:
			return sent
		case permanent(err):
			o.finish(it, res, err)
		default:
			o.retry(it, err, now)
		}
	}
	return sent
}

func (o *Outbox) sendItem(ctx context.Context, addr netip.AddrPort, it OutboxItem) (SendResult, error) {
	size, sum, err := digestPath(it.Path)
	if err != nil || size != it.Size || sum != it.SHA256 {
		return SendResult{}, ErrFileChanged
	}
	return SendWithoutMetadata(ctx, addr, it.Path, it.Metadata, &SendOptions{Name: it.Name})
}

func (o *Outbox) finish(it OutboxItem, res SendResult, err error) {
	o.mu.Lock()
	if i := slices.IndexFunc(o.items, func(x OutboxItem) bool { return x.ID == it.ID }); i >= 0 {
		o.items = slices.Delete(o.items, i, i+1)
		_ = o.saveLocked()
	}
	o.mu.Unlock()
	if o.cfg.OnDone != nil {
		o.cfg.OnDone(it, res, err)
	}
}

func (o *Outbox) retry(it OutboxItem, err error, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	i := slices.IndexFunc(o.items, func(x OutboxItem) bool { return x.ID == it.ID })
	if i < 0 {
		return
	}
	x := &o.items[i]
	x.Attempts++
	backoff := outboxMinBackoff << min(x.Attempts-1, 6)
	x.NextTry = now.Add(min(backoff, outboxMaxBackoff))
	x.LastError = err.Error()
	_ = o.saveLocked()
}

// Run calls RunOnce every interval (at least 5 seconds) until ctx ends.
// The service also calls RunOnce when a peer comes online.
func (o *Outbox) Run(ctx context.Context, every time.Duration) {
	every = max(every, 5*time.Second)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		o.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
