package syncdir

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Client talks to a peer's sync service over one connection. Requests are
// serialized; it is safe for use from several goroutines.
type Client struct {
	conn net.Conn
	br   *bufio.Reader
	mu   sync.Mutex
	// MaxFileSize skips remote entries larger than this (default 64 GiB).
	MaxFileSize int64
}

// Dial connects to the peer's tunnel address (port DefaultPort).
func Dial(ctx context.Context, addr netip.AddrPort) (*Client, error) {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("syncdir: bağlanılamadı: %w", err)
	}
	return &Client{conn: c, br: bufio.NewReaderSize(c, 64<<10)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func statusError(r response) error {
	switch r.Status {
	case stOK, stReady:
		return nil
	case stDenied:
		if r.Error != "" {
			return fmt.Errorf("%w: %s", ErrDenied, r.Error)
		}
		return ErrDenied
	case stNotFound:
		return ErrNotFound
	case stChanged:
		return ErrChanged
	case stQuota:
		return ErrQuota
	case stBad:
		if r.Error != "" {
			return fmt.Errorf("%w: %s", ErrProtocol, r.Error)
		}
		return ErrProtocol
	}
	return errStore
}

var (
	// ErrNotFound is returned for a missing file or object.
	ErrNotFound = errors.New("syncdir: bulunamadı")
	// ErrChanged means the file changed on the peer since its index.
	ErrChanged = errors.New("syncdir: dosya eşte değişti; sonraki eşitlemede yeniden denenecek")
	// ErrQuota means the backup target's quota for this device is full.
	ErrQuota = errors.New("syncdir: yedek hedefindeki kota doldu")
)

// begin locks the connection for one request and arms ctx.
func (c *Client) begin(ctx context.Context) func() {
	c.mu.Lock()
	stop := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
	return func() {
		stop()
		c.mu.Unlock()
	}
}

func (c *Client) send(req request) (response, error) {
	req.V = protoVersion
	_ = c.conn.SetDeadline(time.Now().Add(requestIdle))
	if err := writeFrame(c.conn, req); err != nil {
		return response{}, err
	}
	var r response
	if err := readFrame(c.br, &r); err != nil {
		return response{}, err
	}
	return r, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Folder returns the peer's shared folder id as a pull Source.
func (c *Client) Folder(id string) Source { return &remoteFolder{c: c, id: id} }

type remoteFolder struct {
	c  *Client
	id string
}

func (rf *remoteFolder) Index(ctx context.Context) (Index, error) {
	c := rf.c
	done := c.begin(ctx)
	defer done()
	maxSize := c.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	ix := Index{}
	after := ""
	for {
		r, err := c.send(request{Op: opIndex, Folder: rf.id, After: after})
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		if err := statusError(r); err != nil {
			return nil, err
		}
		for _, e := range r.Entries {
			// The peer is not trusted to send safe names.
			if ValidatePath(e.P) != nil || !e.Entry.valid(1<<62) || e.P <= after {
				return nil, fmt.Errorf("%w: geçersiz dizin girdisi", ErrProtocol)
			}
			after = e.P
			if e.Size <= maxSize {
				ix[e.P] = e.Entry
			}
			if len(ix) > MaxEntries {
				return nil, fmt.Errorf("%w: çok fazla dosya", ErrProtocol)
			}
		}
		if !r.More {
			return ix, nil
		}
		if len(r.Entries) == 0 {
			return nil, ErrProtocol
		}
	}
}

func (rf *remoteFolder) Fetch(ctx context.Context, p string, e Entry, w io.Writer) error {
	c := rf.c
	done := c.begin(ctx)
	defer done()
	r, err := c.send(request{Op: opGet, Folder: rf.id, Path: p, Hash: e.Hash})
	if err != nil {
		return ctxErr(ctx, err)
	}
	if err := statusError(r); err != nil {
		return err
	}
	if r.Size != e.Size {
		return ErrProtocol
	}
	if _, err = io.CopyN(w, &deadlineReader{c: c.conn, r: c.br, idle: dataIdle}, r.Size); err != nil {
		// Unread bytes would be taken for the next answer.
		_ = c.conn.Close()
	}
	return ctxErr(ctx, err)
}

// Store returns the peer's backup store name for this device.
func (c *Client) Store(name string) *RemoteStore { return &RemoteStore{c: c, name: name} }

// RemoteStore is a backup target on a peer.
type RemoteStore struct {
	c    *Client
	name string
}

// Has reports which objects exist.
func (s *RemoteStore) Has(ctx context.Context, kind string, names []string) ([]bool, error) {
	done := s.c.begin(ctx)
	defer done()
	out := make([]bool, 0, len(names))
	for start := 0; start < len(names); start += maxHasNames {
		part := names[start:min(start+maxHasNames, len(names))]
		r, err := s.c.send(request{Op: opHas, Store: s.name, Kind: kind, Names: part})
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		if err := statusError(r); err != nil {
			return nil, err
		}
		if len(r.Have) != len(part) {
			return nil, ErrProtocol
		}
		out = append(out, r.Have...)
	}
	return out, nil
}

// List returns every object name of a kind, sorted.
func (s *RemoteStore) List(ctx context.Context, kind string) ([]string, error) {
	done := s.c.begin(ctx)
	defer done()
	var out []string
	after := ""
	for {
		r, err := s.c.send(request{Op: opList, Store: s.name, Kind: kind, After: after})
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		if err := statusError(r); err != nil {
			return nil, err
		}
		for _, n := range r.Names {
			if !validObject(kind, n) || n <= after {
				return nil, ErrProtocol
			}
			after = n
			out = append(out, n)
		}
		if !r.More {
			return out, nil
		}
		if len(r.Names) == 0 || len(out) > 10*MaxEntries {
			return nil, ErrProtocol
		}
	}
}

// Put uploads exactly size bytes from r as a new object.
func (s *RemoteStore) Put(ctx context.Context, kind, name string, size int64, r io.Reader) error {
	done := s.c.begin(ctx)
	defer done()
	resp, err := s.c.send(request{Op: opPut, Store: s.name, Kind: kind, Name: name, Size: size})
	if err != nil {
		return ctxErr(ctx, err)
	}
	if err := statusError(resp); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(&deadlineWriter{c: s.c.conn, idle: dataIdle}, io.TeeReader(io.LimitReader(r, size), h))
	if err != nil {
		return ctxErr(ctx, err)
	}
	if n != size {
		// The connection is out of step; it cannot be used again.
		_ = s.c.conn.Close()
		return errors.New("syncdir: yüklenecek veri beklenenden kısa")
	}
	_ = s.c.conn.SetDeadline(time.Now().Add(requestIdle))
	if err := writeFrame(s.c.conn, request{V: protoVersion, SHA256: hex.EncodeToString(h.Sum(nil))}); err != nil {
		return ctxErr(ctx, err)
	}
	var final response
	if err := readFrame(s.c.br, &final); err != nil {
		return ctxErr(ctx, err)
	}
	return statusError(final)
}

// Get downloads an object to w and returns its size.
func (s *RemoteStore) Get(ctx context.Context, kind, name string, maxSize int64, w io.Writer) (int64, error) {
	done := s.c.begin(ctx)
	defer done()
	r, err := s.c.send(request{Op: opFetch, Store: s.name, Kind: kind, Name: name})
	if err != nil {
		return 0, ctxErr(ctx, err)
	}
	if err := statusError(r); err != nil {
		return 0, err
	}
	if r.Size < 0 || r.Size > maxSize {
		_ = s.c.conn.Close()
		return 0, ErrProtocol
	}
	n, err := io.CopyN(w, &deadlineReader{c: s.c.conn, r: s.c.br, idle: dataIdle}, r.Size)
	if err != nil {
		_ = s.c.conn.Close()
	}
	return n, ctxErr(ctx, err)
}

// Delete removes an object; the target must allow pruning.
func (s *RemoteStore) Delete(ctx context.Context, kind, name string) error {
	done := s.c.begin(ctx)
	defer done()
	r, err := s.c.send(request{Op: opDel, Store: s.name, Kind: kind, Name: name})
	if err != nil {
		return ctxErr(ctx, err)
	}
	return statusError(r)
}
