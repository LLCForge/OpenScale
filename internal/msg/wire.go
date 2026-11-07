package msg

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Wire protocol: one TCP connection carries one message. The sender
// writes a frame (4-byte big-endian length, then the envelope as JSON)
// and the receiver answers with a frame {"s":"ok"} or {"s":"rejected"}.
// The receiver never says why it refused; the reason goes to its log.

const (
	maxFrame      = 16 << 10
	maxReply      = 256
	dialTimeout   = 10 * time.Second
	ioTimeout     = 20 * time.Second
	maxConns      = 16
	maxClockAhead = 10 * time.Minute
	maxAge        = 7 * 24 * time.Hour
)

// ErrRejected means the recipient refused the message.
var ErrRejected = errors.New("alıcı mesajı kabul etmedi")

type reply struct {
	S string `json:"s"`
}

func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return errors.New("mesaj çerçevesi çok büyük")
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, limit int, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > uint32(limit) {
		return errors.New("geçersiz çerçeve uzunluğu")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("çerçevede fazladan veri")
	}
	return nil
}

// Send delivers env to the listener at addr (the recipient's tunnel
// address and Port).
func Send(ctx context.Context, addr netip.AddrPort, env Envelope) error {
	if err := env.Validate(); err != nil {
		return err
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp4", addr.String())
	if err != nil {
		return fmt.Errorf("alıcıya bağlanılamadı (tünel açık mı, alıcıda 'openscale msg listen' çalışıyor mu, kural tcp/%d portuna izin veriyor mu?): %w", Port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))
	if err := writeFrame(conn, env); err != nil {
		return err
	}
	var r reply
	if err := readFrame(conn, maxReply, &r); err != nil {
		return fmt.Errorf("alıcıdan yanıt alınamadı: %w", err)
	}
	if r.S != "ok" {
		return ErrRejected
	}
	return nil
}

// Peer is a device of the signed document, as the listener sees it.
type Peer struct {
	Name            string
	WireGuardPublic []byte
}

// ServerConfig configures a listener.
type ServerConfig struct {
	// Self returns this device's name and WireGuard private key, read
	// for each message so a key rotation takes effect.
	Self func() (name string, priv []byte, err error)
	// PeerByAddr maps a connection's tunnel source address to a device of
	// the signed document. WireGuard's cryptokey routing makes the source
	// address the sending device's identity; the envelope's sender name
	// and static key must agree with it.
	PeerByAddr func(netip.Addr) (Peer, bool)
	Store      *Store
	// OnMessage is called after a message is stored; may be nil.
	OnMessage func(Message)
	Logger    *slog.Logger
	Now       func() time.Time
}

// Server receives messages.
type Server struct {
	cfg ServerConfig
	sem chan struct{}
	wg  sync.WaitGroup
}

// NewServer validates cfg.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Self == nil || cfg.PeerByAddr == nil || cfg.Store == nil {
		return nil, errors.New("msg: Self, PeerByAddr and Store are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, sem: make(chan struct{}, maxConns)}, nil
}

// Serve accepts connections on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer s.wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(ioTimeout))
			status := "ok"
			if err := s.handle(conn); err != nil {
				status = "rejected"
				s.cfg.Logger.Warn("message refused", "error", err.Error())
			}
			_ = writeFrame(conn, reply{S: status})
		}()
	}
}

func (s *Server) handle(conn net.Conn) error {
	var from netip.Addr
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		from = ta.AddrPort().Addr().Unmap()
	}
	var env Envelope
	if err := readFrame(conn, maxFrame, &env); err != nil {
		return fmt.Errorf("frame: %w", err)
	}
	m, err := s.accept(from, env)
	if err != nil {
		return err
	}
	if err := s.cfg.Store.AddIncoming(m); err != nil {
		if errors.Is(err, ErrDuplicate) {
			// The sender retried after a lost reply: acknowledge again.
			return nil
		}
		return fmt.Errorf("store: %w", err)
	}
	if s.cfg.OnMessage != nil {
		s.cfg.OnMessage(m)
	}
	return nil
}

// accept checks env against the source address and the signed document
// and opens it.
func (s *Server) accept(from netip.Addr, env Envelope) (Message, error) {
	if err := env.Validate(); err != nil {
		return Message{}, err
	}
	peer, ok := s.cfg.PeerByAddr(from)
	if !ok {
		return Message{}, errors.New("source is not a device of the network")
	}
	if env.From != peer.Name {
		return Message{}, fmt.Errorf("sender name %q does not match source device %q", env.From, peer.Name)
	}
	selfName, priv, err := s.cfg.Self()
	if err != nil {
		return Message{}, err
	}
	defer clear(priv)
	if env.To != selfName {
		return Message{}, fmt.Errorf("message is for %q, not this device", env.To)
	}
	now := s.cfg.Now()
	at := time.Unix(env.Time, 0)
	if at.After(now.Add(maxClockAhead)) || at.Before(now.Add(-maxAge)) {
		return Message{}, errors.New("message time outside the accepted window")
	}
	text, err := Open(priv, peer.WireGuardPublic, env)
	if err != nil {
		return Message{}, err
	}
	return Message{ID: env.ID, Peer: peer.Name, At: at, Text: text}, nil
}
