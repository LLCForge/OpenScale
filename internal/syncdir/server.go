package syncdir

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
)

// Access is what a peer may do; the zero value allows nothing.
type Access struct {
	// Peer is the device name (used for logs and as the backup owner).
	Peer string
	// Folders lists the folder IDs the peer may read.
	Folders []string
	// Backup lets the peer keep encrypted backups here (#137).
	Backup bool
	// Quota bounds the bytes the peer's backups may use here.
	Quota int64
	// AllowPrune lets the peer delete its own old backup objects. Off by
	// default: a stolen or compromised source then cannot destroy its
	// backups (append only).
	AllowPrune bool
}

// ServerConfig configures a Server.
type ServerConfig struct {
	// ListenAddr is the device's tunnel address; wildcard addresses are
	// rejected so the service is never reachable outside the tunnel.
	ListenAddr netip.AddrPort
	// Authorize answers for the device at a tunnel address. Required; it
	// is asked again for every request, so revoked access ends at once.
	Authorize func(remote netip.Addr) Access
	// Folder returns a shared folder by ID, or nil.
	Folder func(id string) *Folder
	// BackupDir holds the backups of other devices; empty refuses every
	// backup request.
	BackupDir string
	// MaxObject bounds one backup object (default 80 GiB).
	MaxObject int64
	// Logger receives structured logs; nil discards them. File names are
	// never logged.
	Logger *slog.Logger
}

const (
	maxConns         = 16
	defaultMaxObject = int64(80) << 30
)

// ErrInvalidListenAddr is returned for a missing or wildcard address.
var ErrInvalidListenAddr = errors.New("syncdir: dinleme adresi belirli bir tünel adresi olmalı")

// ValidateListenAddr rejects invalid and wildcard listen addresses.
func ValidateListenAddr(a netip.AddrPort) error {
	if !a.IsValid() || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Port() == 0 {
		return ErrInvalidListenAddr
	}
	return nil
}

// Server serves shared folders read-only and stores other devices'
// encrypted backups.
type Server struct {
	cfg   ServerConfig
	log   *slog.Logger
	store *blobStore

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// NewServer validates cfg.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Authorize == nil {
		return nil, errors.New("syncdir: Authorize geri çağrısı zorunlu")
	}
	if cfg.Folder == nil {
		cfg.Folder = func(string) *Folder { return nil }
	}
	if cfg.MaxObject <= 0 {
		cfg.MaxObject = defaultMaxObject
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, log: log, conns: map[net.Conn]struct{}{}}
	if cfg.BackupDir != "" {
		st, err := openBlobStore(cfg.BackupDir, cfg.MaxObject)
		if err != nil {
			return nil, err
		}
		s.store = st
	}
	return s, nil
}

// ListenAndServe listens on the tunnel address until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := ValidateListenAddr(s.cfg.ListenAddr); err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr.String())
	if err != nil {
		return fmt.Errorf("syncdir: dinlenemedi: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections from ln (which it takes over) until ctx ends
// or Close is called.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		if err := ValidateListenAddr(ta.AddrPort()); err != nil {
			_ = ln.Close()
			return err
		}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return net.ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		s.mu.Lock()
		if s.closed || len(s.conns) >= maxConns {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				_ = c.Close()
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
			}()
			s.handle(c)
		}()
	}
}

// Close stops the server and waits for its connections.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}
	s.closed = true
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if s.store != nil {
		_ = s.store.root.Close()
	}
	return err
}

type connState struct {
	c        net.Conn
	br       *bufio.Reader
	remote   netip.Addr
	snapshot map[string]*indexSnapshot
}

type indexSnapshot struct {
	ix    Index
	paths []string
}

func (s *Server) handle(c net.Conn) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	st := &connState{c: c, br: bufio.NewReaderSize(c, 64<<10), remote: ta.AddrPort().Addr().Unmap(), snapshot: map[string]*indexSnapshot{}}
	for {
		_ = c.SetReadDeadline(time.Now().Add(requestIdle))
		var req request
		if err := readFrame(st.br, &req); err != nil {
			if errors.Is(err, ErrProtocol) {
				_ = s.reply(st, response{Status: stBad})
			}
			return
		}
		if req.V != protoVersion {
			_ = s.reply(st, response{Status: stBad, Error: "desteklenmeyen protokol sürümü"})
			return
		}
		acc := s.cfg.Authorize(st.remote)
		if err := s.dispatch(st, acc, req); err != nil {
			if !errors.Is(err, io.EOF) {
				s.log.Debug("eşitleme bağlantısı kapatıldı", "peer", acc.Peer, "op", req.Op, "err", err)
			}
			return
		}
	}
}

func (s *Server) reply(st *connState, r response) error {
	_ = st.c.SetWriteDeadline(time.Now().Add(dataIdle))
	return writeFrame(st.c, r)
}

func (s *Server) dispatch(st *connState, acc Access, req request) error {
	switch req.Op {
	case opIndex:
		return s.serveIndex(st, acc, req)
	case opGet:
		return s.serveGet(st, acc, req)
	case opHas, opPut, opFetch, opList, opDel:
		if s.store == nil || !acc.Backup || !ValidID(acc.Peer) || !ValidID(req.Store) {
			return s.reply(st, response{Status: stDenied})
		}
		return s.store.serve(s, st, acc, req)
	}
	return s.reply(st, response{Status: stBad})
}

func (s *Server) folderFor(acc Access, id string) *Folder {
	if !ValidID(id) || !slices.Contains(acc.Folders, id) {
		return nil
	}
	return s.cfg.Folder(id)
}

func (s *Server) serveIndex(st *connState, acc Access, req request) error {
	f := s.folderFor(acc, req.Folder)
	if f == nil {
		s.log.Info("eşitleme isteği reddedildi", "peer", acc.Peer)
		return s.reply(st, response{Status: stDenied})
	}
	snap := st.snapshot[req.Folder]
	if req.After == "" || snap == nil {
		ix, err := f.Scan()
		if errors.Is(err, ErrSuspended) {
			// SECURITY: a folder that may hold files encrypted by
			// ransomware is not served, so peers keep their good copies.
			s.log.Warn("paylaşılan klasör fidye yazılımı şüphesiyle durduruldu", "folder", req.Folder)
			return s.reply(st, response{Status: stDenied, Error: "klasör sahibin cihazında fidye yazılımı şüphesiyle durduruldu"})
		}
		if err != nil {
			s.log.Warn("paylaşılan klasör taranamadı", "folder", req.Folder, "err", err)
			return s.reply(st, response{Status: stError})
		}
		snap = &indexSnapshot{ix: ix, paths: make([]string, 0, len(ix))}
		for p := range ix {
			snap.paths = append(snap.paths, p)
		}
		sort.Strings(snap.paths)
		st.snapshot[req.Folder] = snap
	}
	i := 0
	if req.After != "" {
		i = sort.SearchStrings(snap.paths, req.After)
		if i < len(snap.paths) && snap.paths[i] == req.After {
			i++
		}
	}
	resp := response{Status: stOK}
	size := 0
	for ; i < len(snap.paths) && size < indexPageSize; i++ {
		p := snap.paths[i]
		resp.Entries = append(resp.Entries, wireEntry{P: p, Entry: snap.ix[p]})
		size += len(p) + 120
	}
	resp.More = i < len(snap.paths)
	return s.reply(st, resp)
}

func (s *Server) serveGet(st *connState, acc Access, req request) error {
	f := s.folderFor(acc, req.Folder)
	if f == nil {
		return s.reply(st, response{Status: stDenied})
	}
	if ValidatePath(req.Path) != nil {
		return s.reply(st, response{Status: stBad})
	}
	snap := st.snapshot[req.Folder]
	if snap == nil {
		return s.reply(st, response{Status: stBad, Error: "önce dizin istenmeli"})
	}
	e, ok := snap.ix[req.Path]
	if !ok || e.Hash != req.Hash {
		return s.reply(st, response{Status: stNotFound})
	}
	r, err := f.root.Open(req.Path)
	if err != nil {
		return s.reply(st, response{Status: stChanged})
	}
	defer r.Close()
	info, err := r.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != e.Size || mtimeOf(info) != e.MTime {
		// Changed since the index; the peer verifies the hash anyway and
		// tries again on its next pull.
		return s.reply(st, response{Status: stChanged})
	}
	if err := s.reply(st, response{Status: stOK, Size: e.Size}); err != nil {
		return err
	}
	_, err = io.CopyN(&deadlineWriter{c: st.c, idle: dataIdle}, r, e.Size)
	return err
}
