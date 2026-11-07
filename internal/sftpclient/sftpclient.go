// Package sftpclient is a minimal SFTP version 3 client (draft-ietf-secsh-
// filexfer-02) for the panel's file browser next to the SSH terminal
// (#855, ADR-0203). It speaks the protocol over any byte stream; the panel
// opens that stream as the "sftp" subsystem of a connection made with
// internal/sshclient, so the host key pin and the account are the
// terminal's. Only the requests the browser needs are implemented: OPEN,
// READ, WRITE, CLOSE, OPENDIR, READDIR, STAT, LSTAT, REALPATH, MKDIR,
// REMOVE, RMDIR and RENAME. No dependency beyond the standard library
// (ADR-0002).
//
// Everything the server sends is untrusted: packet sizes, string lengths
// and entry counts are bounded, and names that could not be a single path
// element are dropped from directory listings.
package sftpclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Packet types.
const (
	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpLstat    = 7
	fxpOpendir  = 11
	fxpReaddir  = 12
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRealpath = 16
	fxpStat     = 17
	fxpRename   = 18
	fxpStatus   = 101
	fxpHandle   = 102
	fxpData     = 103
	fxpName     = 104
	fxpAttrs    = 105
)

// Open flags.
const (
	fxfRead   = 0x01
	fxfWrite  = 0x02
	fxfCreat  = 0x08
	fxfTrunc  = 0x10
	fxfExcl   = 0x20
	attrSize  = 0x01
	attrUID   = 0x02
	attrPerm  = 0x04
	attrTime  = 0x08
	attrExt   = 0x80000000
	sftpProto = 3
)

// Status codes.
const (
	StatusOK               = 0
	StatusEOF              = 1
	StatusNoSuchFile       = 2
	StatusPermissionDenied = 3
	StatusFailure          = 4
	StatusBadMessage       = 5
	StatusOpUnsupported    = 8
)

const (
	// MaxPacket bounds a packet from the server.
	MaxPacket = 1 << 20
	// ChunkSize is the size of one READ or WRITE.
	ChunkSize = 32 << 10
	// MaxPath bounds a remote path.
	MaxPath = 4096
	// MaxEntries bounds one directory listing.
	MaxEntries = 10000
	// window is the number of READ or WRITE requests in flight.
	window = 8
	// handshakeTimeout bounds INIT/VERSION when the context has none.
	handshakeTimeout = 20 * time.Second
	maxHandle        = 256
	maxStatusMsg     = 1024
	maxExtensions    = 64
)

var (
	// ErrClosed is returned after the connection ended.
	ErrClosed = errors.New("sftpclient: bağlantı kapandı")
	// ErrProtocol is returned for a malformed or unexpected packet.
	ErrProtocol = errors.New("sftpclient: protokol hatası")
	// ErrTooLarge is returned when a transfer passes its limit.
	ErrTooLarge = errors.New("sftpclient: dosya boyut sınırını aşıyor")
	// ErrTooMany is returned when a directory has more than MaxEntries.
	ErrTooMany = errors.New("sftpclient: klasörde çok fazla girdi var")
	// ErrBadPath is returned for an empty, too long or malformed path.
	ErrBadPath = errors.New("sftpclient: geçersiz yol")
)

// StatusError is a failure the server reported.
type StatusError struct {
	Code    uint32
	Message string
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("sftpclient: sunucu hatası %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("sftpclient: sunucu hatası %d", e.Code)
}

// Is maps the codes to the fs errors.
func (e *StatusError) Is(target error) bool {
	switch target {
	case fs.ErrNotExist:
		return e.Code == StatusNoSuchFile
	case fs.ErrPermission:
		return e.Code == StatusPermissionDenied
	case io.EOF:
		return e.Code == StatusEOF
	}
	return false
}

// FileInfo describes a remote file.
type FileInfo struct {
	Name    string      `json:"name"`
	Size    int64       `json:"size"`
	Mode    fs.FileMode `json:"-"`
	ModTime time.Time   `json:"mtime"`
	// Perm is the POSIX permission bits (0 when the server sent none).
	Perm uint32 `json:"perm"`
	Dir  bool   `json:"dir"`
	Link bool   `json:"link"`
	// Regular is a plain file.
	Regular bool `json:"regular"`
}

type packet struct {
	typ  byte
	data []byte // after the request id
}

// Client is one SFTP session. Its methods may be called concurrently.
type Client struct {
	rw io.ReadWriteCloser

	wmu sync.Mutex

	mu      sync.Mutex
	nextID  uint32
	pending map[uint32]chan packet
	err     error
	done    chan struct{}
}

// New starts the session on rw (the "sftp" subsystem channel) and takes
// ownership of it.
func New(ctx context.Context, rw io.ReadWriteCloser) (*Client, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
	}
	stop := context.AfterFunc(ctx, func() { _ = rw.Close() })
	err := handshake(rw)
	if !stop() {
		_ = rw.Close()
		return nil, fmt.Errorf("sftpclient: el sıkışma zaman aşımı: %w", errors.Join(ctx.Err(), err))
	}
	if err != nil {
		_ = rw.Close()
		return nil, err
	}
	c := &Client{rw: rw, pending: map[uint32]chan packet{}, done: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func handshake(rw io.ReadWriter) error {
	var init [9]byte
	binary.BigEndian.PutUint32(init[0:], 5)
	init[4] = fxpInit
	binary.BigEndian.PutUint32(init[5:], sftpProto)
	if _, err := rw.Write(init[:]); err != nil {
		return fmt.Errorf("sftpclient: başlangıç gönderilemedi: %w", err)
	}
	typ, body, err := readPacket(rw)
	if err != nil {
		return fmt.Errorf("sftpclient: sunucu yanıt vermedi: %w", err)
	}
	if typ != fxpVersion {
		return fmt.Errorf("%w: sürüm bekleniyordu", ErrProtocol)
	}
	r := reader{b: body}
	v, ok := r.u32()
	if !ok || v < sftpProto {
		return fmt.Errorf("%w: sunucu SFTP sürüm 3 desteklemiyor", ErrProtocol)
	}
	// Extensions are read and ignored.
	for n := 0; r.left() > 0; n++ {
		if n >= maxExtensions {
			return fmt.Errorf("%w: çok fazla uzantı", ErrProtocol)
		}
		if _, ok := r.str(MaxPacket); !ok {
			return ErrProtocol
		}
		if _, ok := r.str(MaxPacket); !ok {
			return ErrProtocol
		}
	}
	return nil
}

// readPacket reads one length-prefixed packet.
func readPacket(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 1 || n > MaxPacket {
		return 0, nil, fmt.Errorf("%w: paket boyutu %d", ErrProtocol, n)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[4], body, nil
}

func (c *Client) readLoop() {
	var err error
	for {
		var typ byte
		var body []byte
		typ, body, err = readPacket(c.rw)
		if err != nil {
			break
		}
		if len(body) < 4 {
			err = ErrProtocol
			break
		}
		id := binary.BigEndian.Uint32(body)
		c.mu.Lock()
		ch, ok := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if ok {
			ch <- packet{typ: typ, data: body[4:]}
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = ErrClosed
	}
	c.mu.Lock()
	c.err = err
	c.pending = map[uint32]chan packet{}
	c.mu.Unlock()
	close(c.done)
	_ = c.rw.Close()
}

// Close ends the session.
func (c *Client) Close() error {
	err := c.rw.Close()
	<-c.done
	return err
}

// Err is why the session ended, nil while it runs.
func (c *Client) Err() error {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.err
	default:
		return nil
	}
}

// start sends a request and returns the channel its answer arrives on.
func (c *Client) start(typ byte, payload []byte) (uint32, chan packet, error) {
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return 0, nil, ErrClosed
	default:
	}
	c.nextID++
	id := c.nextID
	ch := make(chan packet, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	msg := make([]byte, 9, 9+len(payload))
	binary.BigEndian.PutUint32(msg[0:], uint32(5+len(payload)))
	msg[4] = typ
	binary.BigEndian.PutUint32(msg[5:], id)
	msg = append(msg, payload...)
	c.wmu.Lock()
	_, err := c.rw.Write(msg)
	c.wmu.Unlock()
	if err != nil {
		c.forget(id)
		return 0, nil, fmt.Errorf("sftpclient: istek gönderilemedi: %w", err)
	}
	return id, ch, nil
}

func (c *Client) forget(id uint32) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *Client) wait(ctx context.Context, id uint32, ch chan packet) (packet, error) {
	select {
	case p := <-ch:
		return p, nil
	case <-ctx.Done():
		c.forget(id)
		return packet{}, ctx.Err()
	case <-c.done:
		// The answer may have arrived just before the end.
		select {
		case p := <-ch:
			return p, nil
		default:
		}
		if err := c.Err(); err != nil {
			return packet{}, err
		}
		return packet{}, ErrClosed
	}
}

func (c *Client) call(ctx context.Context, typ byte, payload []byte) (packet, error) {
	id, ch, err := c.start(typ, payload)
	if err != nil {
		return packet{}, err
	}
	return c.wait(ctx, id, ch)
}

// status turns a STATUS answer into nil (OK) or an error.
func status(p packet) error {
	if p.typ != fxpStatus {
		return fmt.Errorf("%w: durum bekleniyordu (%d)", ErrProtocol, p.typ)
	}
	r := reader{b: p.data}
	code, ok := r.u32()
	if !ok {
		return ErrProtocol
	}
	if code == StatusOK {
		return nil
	}
	m, _ := r.str(maxStatusMsg)
	return &StatusError{Code: code, Message: cleanText(m)}
}

func (c *Client) expectStatus(ctx context.Context, typ byte, payload []byte) error {
	p, err := c.call(ctx, typ, payload)
	if err != nil {
		return err
	}
	return status(p)
}

func (c *Client) expectHandle(ctx context.Context, typ byte, payload []byte) (string, error) {
	p, err := c.call(ctx, typ, payload)
	if err != nil {
		return "", err
	}
	if p.typ == fxpStatus {
		if err := status(p); err != nil {
			return "", err
		}
		return "", ErrProtocol
	}
	if p.typ != fxpHandle {
		return "", fmt.Errorf("%w: tanıtıcı bekleniyordu", ErrProtocol)
	}
	r := reader{b: p.data}
	h, ok := r.str(maxHandle)
	if !ok || h == "" {
		return "", ErrProtocol
	}
	return h, nil
}

func checkPath(p string) error {
	if p == "" || len(p) > MaxPath || strings.ContainsRune(p, 0) || !utf8.ValidString(p) {
		return ErrBadPath
	}
	return nil
}

// RealPath asks the server for the absolute form of p ("." is the home
// directory).
func (c *Client) RealPath(ctx context.Context, p string) (string, error) {
	if err := checkPath(p); err != nil {
		return "", err
	}
	pk, err := c.call(ctx, fxpRealpath, putStr(nil, p))
	if err != nil {
		return "", err
	}
	if pk.typ == fxpStatus {
		if err := status(pk); err != nil {
			return "", err
		}
		return "", ErrProtocol
	}
	if pk.typ != fxpName {
		return "", ErrProtocol
	}
	r := reader{b: pk.data}
	n, ok := r.u32()
	if !ok || n != 1 {
		return "", ErrProtocol
	}
	name, ok := r.str(MaxPath)
	if !ok || checkPath(name) != nil {
		return "", ErrProtocol
	}
	return name, nil
}

func (c *Client) stat(ctx context.Context, typ byte, p string) (FileInfo, error) {
	if err := checkPath(p); err != nil {
		return FileInfo{}, err
	}
	pk, err := c.call(ctx, typ, putStr(nil, p))
	if err != nil {
		return FileInfo{}, err
	}
	if pk.typ == fxpStatus {
		if err := status(pk); err != nil {
			return FileInfo{}, err
		}
		return FileInfo{}, ErrProtocol
	}
	if pk.typ != fxpAttrs {
		return FileInfo{}, ErrProtocol
	}
	r := reader{b: pk.data}
	fi, ok := r.attrs()
	if !ok {
		return FileInfo{}, ErrProtocol
	}
	fi.Name = baseName(p)
	return fi, nil
}

// Stat describes p, following a symbolic link.
func (c *Client) Stat(ctx context.Context, p string) (FileInfo, error) {
	return c.stat(ctx, fxpStat, p)
}

// Lstat describes p itself.
func (c *Client) Lstat(ctx context.Context, p string) (FileInfo, error) {
	return c.stat(ctx, fxpLstat, p)
}

// ReadDir lists a directory without "." and "..", in the server's order.
// It returns ErrTooMany after MaxEntries entries.
func (c *Client) ReadDir(ctx context.Context, p string) ([]FileInfo, error) {
	if err := checkPath(p); err != nil {
		return nil, err
	}
	h, err := c.expectHandle(ctx, fxpOpendir, putStr(nil, p))
	if err != nil {
		return nil, err
	}
	defer c.closeHandle(h)
	var out []FileInfo
	for {
		pk, err := c.call(ctx, fxpReaddir, putStr(nil, h))
		if err != nil {
			return nil, err
		}
		if pk.typ == fxpStatus {
			err := status(pk)
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			if err == nil {
				err = ErrProtocol
			}
			return nil, err
		}
		if pk.typ != fxpName {
			return nil, ErrProtocol
		}
		r := reader{b: pk.data}
		n, ok := r.u32()
		if !ok || n > MaxEntries {
			return nil, ErrProtocol
		}
		for range n {
			name, ok1 := r.str(MaxPath)
			_, ok2 := r.str(MaxPacket)
			fi, ok3 := r.attrs()
			if !ok1 || !ok2 || !ok3 {
				return nil, ErrProtocol
			}
			if name == "." || name == ".." || !ValidName(name) {
				continue
			}
			fi.Name = name
			if len(out) >= MaxEntries {
				return out, ErrTooMany
			}
			out = append(out, fi)
		}
	}
}

// ValidName reports whether name can be one path element: not empty, no
// "/" or NUL, not "." or "..", valid UTF-8 and at most 255 bytes.
func ValidName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 255 || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsAny(name, "/\x00")
}

// Mkdir creates a directory (mode 0755, the server's umask applies).
func (c *Client) Mkdir(ctx context.Context, p string) error {
	if err := checkPath(p); err != nil {
		return err
	}
	b := putStr(nil, p)
	b = binary.BigEndian.AppendUint32(b, attrPerm)
	b = binary.BigEndian.AppendUint32(b, 0o755)
	return c.expectStatus(ctx, fxpMkdir, b)
}

// Remove deletes a file.
func (c *Client) Remove(ctx context.Context, p string) error {
	if err := checkPath(p); err != nil {
		return err
	}
	return c.expectStatus(ctx, fxpRemove, putStr(nil, p))
}

// RemoveDir deletes an empty directory.
func (c *Client) RemoveDir(ctx context.Context, p string) error {
	if err := checkPath(p); err != nil {
		return err
	}
	return c.expectStatus(ctx, fxpRmdir, putStr(nil, p))
}

// Rename moves oldPath to newPath; SFTP v3 servers refuse an existing
// target.
func (c *Client) Rename(ctx context.Context, oldPath, newPath string) error {
	if checkPath(oldPath) != nil || checkPath(newPath) != nil {
		return ErrBadPath
	}
	return c.expectStatus(ctx, fxpRename, putStr(putStr(nil, oldPath), newPath))
}

func (c *Client) closeHandle(h string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.expectStatus(ctx, fxpClose, putStr(nil, h))
}

func (c *Client) open(ctx context.Context, p string, flags uint32, perm uint32) (string, error) {
	if err := checkPath(p); err != nil {
		return "", err
	}
	b := putStr(nil, p)
	b = binary.BigEndian.AppendUint32(b, flags)
	if perm != 0 {
		b = binary.BigEndian.AppendUint32(b, attrPerm)
		b = binary.BigEndian.AppendUint32(b, perm)
	} else {
		b = binary.BigEndian.AppendUint32(b, 0)
	}
	return c.expectHandle(ctx, fxpOpen, b)
}

func readReq(h string, off uint64, n uint32) []byte {
	b := putStr(nil, h)
	b = binary.BigEndian.AppendUint64(b, off)
	return binary.BigEndian.AppendUint32(b, n)
}

// Download copies the remote file p into w and returns the bytes written.
// More than limit bytes (limit > 0) stop it with ErrTooLarge. A file that
// is not a regular file is refused.
func (c *Client) Download(ctx context.Context, p string, w io.Writer, limit int64) (int64, error) {
	fi, err := c.Stat(ctx, p)
	if err != nil {
		return 0, err
	}
	if !fi.Regular {
		return 0, fmt.Errorf("sftpclient: %w: normal dosya değil", fs.ErrInvalid)
	}
	if limit > 0 && fi.Size > limit {
		return 0, ErrTooLarge
	}
	h, err := c.open(ctx, p, fxfRead, 0)
	if err != nil {
		return 0, err
	}
	defer c.closeHandle(h)

	type inflight struct {
		id  uint32
		ch  chan packet
		off uint64
	}
	var queue []inflight
	// drain waits for the requests still in flight so their answers do
	// not stay pending.
	drain := func() {
		for _, q := range queue {
			_, _ = c.wait(ctx, q.id, q.ch)
		}
		queue = nil
	}
	var written int64
	next := uint64(0)
	for {
		for len(queue) < window {
			id, ch, err := c.start(fxpRead, readReq(h, next, ChunkSize))
			if err != nil {
				drain()
				return written, err
			}
			queue = append(queue, inflight{id: id, ch: ch, off: next})
			next += ChunkSize
		}
		q := queue[0]
		queue = queue[1:]
		pk, err := c.wait(ctx, q.id, q.ch)
		if err != nil {
			drain()
			return written, err
		}
		if pk.typ == fxpStatus {
			serr := status(pk)
			if errors.Is(serr, io.EOF) {
				drain()
				return written, nil
			}
			if serr == nil {
				serr = ErrProtocol
			}
			drain()
			return written, serr
		}
		if pk.typ != fxpData {
			drain()
			return written, ErrProtocol
		}
		r := reader{b: pk.data}
		data, ok := r.bytes(ChunkSize)
		if !ok {
			drain()
			return written, ErrProtocol
		}
		if q.off != uint64(written) {
			drain()
			return written, ErrProtocol
		}
		if limit > 0 && written+int64(len(data)) > limit {
			drain()
			return written, ErrTooLarge
		}
		if len(data) > 0 {
			n, werr := w.Write(data)
			written += int64(n)
			if werr != nil {
				drain()
				return written, werr
			}
		}
		if len(data) < ChunkSize {
			// A short answer: the requests after it asked for offsets
			// past a gap, so they are dropped and reading goes on from
			// here (or ends on the EOF that follows).
			drain()
			if len(data) == 0 {
				return written, nil
			}
			next = uint64(written)
		}
	}
}

// Upload writes r to the new remote file p (refused when p exists) and
// returns the bytes written. More than limit bytes (limit > 0) stop it
// with ErrTooLarge and remove the partial file.
func (c *Client) Upload(ctx context.Context, r io.Reader, p string, limit int64) (int64, error) {
	h, err := c.open(ctx, p, fxfWrite|fxfCreat|fxfExcl|fxfTrunc, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := c.uploadHandle(ctx, r, h, limit)
	c.closeHandle(h)
	if err != nil {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = c.Remove(rctx, p)
		cancel()
	}
	return n, err
}

func (c *Client) uploadHandle(ctx context.Context, r io.Reader, h string, limit int64) (int64, error) {
	type inflight struct {
		id uint32
		ch chan packet
	}
	var queue []inflight
	collect := func() error {
		q := queue[0]
		queue = queue[1:]
		pk, err := c.wait(ctx, q.id, q.ch)
		if err != nil {
			return err
		}
		return status(pk)
	}
	finish := func(first error) error {
		for len(queue) > 0 {
			if err := collect(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	buf := make([]byte, ChunkSize)
	var off int64
	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			if limit > 0 && off+int64(n) > limit {
				return off, finish(ErrTooLarge)
			}
			b := putStr(nil, h)
			b = binary.BigEndian.AppendUint64(b, uint64(off))
			b = putBytes(b, buf[:n])
			id, ch, err := c.start(fxpWrite, b)
			if err != nil {
				return off, finish(err)
			}
			queue = append(queue, inflight{id: id, ch: ch})
			off += int64(n)
			if len(queue) >= window {
				if err := collect(); err != nil {
					return off, finish(err)
				}
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return off, finish(nil)
		}
		if rerr != nil {
			return off, finish(rerr)
		}
	}
}

// --- encoding ---

func putStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func putBytes(b, p []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
	return append(b, p...)
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) left() int { return len(r.b) - r.off }

func (r *reader) u32() (uint32, bool) {
	if r.left() < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.left() < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v, true
}

func (r *reader) bytes(limit int) ([]byte, bool) {
	n, ok := r.u32()
	if !ok || int64(n) > int64(limit) || int64(n) > int64(r.left()) {
		return nil, false
	}
	v := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return v, true
}

func (r *reader) str(limit int) (string, bool) {
	b, ok := r.bytes(limit)
	return string(b), ok
}

// attrs reads an ATTRS structure.
func (r *reader) attrs() (FileInfo, bool) {
	var fi FileInfo
	flags, ok := r.u32()
	if !ok {
		return fi, false
	}
	if flags&attrSize != 0 {
		v, ok := r.u64()
		if !ok || v > 1<<62 {
			return fi, false
		}
		fi.Size = int64(v)
	}
	if flags&attrUID != 0 {
		if _, ok := r.u64(); !ok {
			return fi, false
		}
	}
	if flags&attrPerm != 0 {
		v, ok := r.u32()
		if !ok {
			return fi, false
		}
		fi.Perm = v & 0o7777
		fi.Mode = posixMode(v)
		fi.Dir = fi.Mode.IsDir()
		fi.Link = fi.Mode&fs.ModeSymlink != 0
		fi.Regular = fi.Mode.IsRegular()
	}
	if flags&attrTime != 0 {
		if _, ok := r.u32(); !ok { // atime
			return fi, false
		}
		m, ok := r.u32()
		if !ok {
			return fi, false
		}
		fi.ModTime = time.Unix(int64(m), 0).UTC()
	}
	if flags&attrExt != 0 {
		n, ok := r.u32()
		if !ok || n > maxExtensions {
			return fi, false
		}
		for range n {
			if _, ok := r.str(MaxPacket); !ok {
				return fi, false
			}
			if _, ok := r.str(MaxPacket); !ok {
				return fi, false
			}
		}
	}
	return fi, true
}

// posixMode converts st_mode bits.
func posixMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o040000:
		mode |= fs.ModeDir
	case 0o120000:
		mode |= fs.ModeSymlink
	case 0o100000:
	case 0o020000:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case 0o060000:
		mode |= fs.ModeDevice
	case 0o010000:
		mode |= fs.ModeNamedPipe
	case 0o140000:
		mode |= fs.ModeSocket
	default:
		mode |= fs.ModeIrregular
	}
	return mode
}

func baseName(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// cleanText keeps a server message printable.
func cleanText(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
