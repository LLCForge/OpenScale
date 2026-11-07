package dbuswire

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bus names and paths of the message bus itself.
const (
	BusName      = "org.freedesktop.DBus"
	BusPath      = ObjectPath("/org/freedesktop/DBus")
	BusInterface = "org.freedesktop.DBus"
)

const (
	// defaultCallTimeout applies when the context has no deadline (the
	// same 25 s libdbus uses).
	defaultCallTimeout = 25 * time.Second
	// authTimeout bounds connecting and authenticating.
	authTimeout = 10 * time.Second
	// writeTimeout bounds one write; a bus that stops reading ends the
	// connection instead of blocking every caller.
	writeTimeout = 10 * time.Second
	// maxPending bounds calls waiting for a reply.
	maxPending = 512
	// callQueue bounds incoming method calls waiting for a handler.
	callQueue = 64
	// maxSubscriptions bounds signal subscriptions.
	maxSubscriptions = 128
)

// ErrClosed: the connection is closed.
var ErrClosed = errors.New("dbus: bağlantı kapalı")

// Error is an ERROR reply.
type Error struct {
	Name string
	// Message is the first string argument, if any.
	Message string
	Body    []any
}

func (e *Error) Error() string {
	if e.Message != "" {
		return "dbus: " + e.Name + ": " + e.Message
	}
	return "dbus: " + e.Name
}

// Standard error names.
const (
	ErrNameFailed          = "org.freedesktop.DBus.Error.Failed"
	ErrNameUnknownMethod   = "org.freedesktop.DBus.Error.UnknownMethod"
	ErrNameUnknownObject   = "org.freedesktop.DBus.Error.UnknownObject"
	ErrNameUnknownIface    = "org.freedesktop.DBus.Error.UnknownInterface"
	ErrNameUnknownProperty = "org.freedesktop.DBus.Error.UnknownProperty"
	ErrNameReadOnly        = "org.freedesktop.DBus.Error.PropertyReadOnly"
	ErrNameInvalidArgs     = "org.freedesktop.DBus.Error.InvalidArgs"
	ErrNameLimitsExceeded  = "org.freedesktop.DBus.Error.LimitsExceeded"
	ErrNameServiceUnknown  = "org.freedesktop.DBus.Error.ServiceUnknown"
	ErrNameNameHasNoOwner  = "org.freedesktop.DBus.Error.NameHasNoOwner"
)

// Options change how Dial connects.
type Options struct {
	// UnixFD asks the bus to pass file descriptors (Linux only).
	UnixFD bool
	// uid overrides the authenticating user id (tests).
	uid string
}

// Conn is a connection to a message bus.
type Conn struct {
	nc     net.Conn
	tr     *fdConn
	r      *bufio.Reader
	wmu    sync.Mutex
	serial atomic.Uint32
	unixFD bool
	name   string

	mu      sync.Mutex
	pending map[uint32]chan *Message
	subs    map[int]*Subscription
	nextSub int
	objects map[ObjectPath]map[string]*Interface
	closed  bool
	err     error
	done    chan struct{}
	calls   chan *Message
}

// DialSession connects to the user's session bus.
func DialSession(ctx context.Context, opt Options) (*Conn, error) {
	eps, err := SessionEndpoints()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, ep := range eps {
		c, err := Dial(ctx, ep, opt)
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// Dial connects to ep, authenticates and says Hello.
func Dial(ctx context.Context, ep Endpoint, opt Options) (*Conn, error) {
	if ep.Abstract != "" && !abstractSupported {
		return nil, fmt.Errorf("dbus: soyut soket bu sistemde yok")
	}
	actx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	var d net.Dialer
	nc, err := d.DialContext(actx, "unix", ep.dialAddr())
	if err != nil {
		return nil, fmt.Errorf("dbus: %s: %w", ep, err)
	}
	if opt.uid == "" {
		opt.uid = strconv.Itoa(os.Getuid())
	}
	c, err := newConn(actx, nc, opt)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	if err := c.hello(actx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// newConn authenticates on nc and starts the reader; the caller says
// Hello on a bus.
func newConn(ctx context.Context, nc net.Conn, opt Options) (*Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	} else {
		_ = nc.SetDeadline(time.Now().Add(authTimeout))
	}
	tr := &fdConn{Conn: nc}
	r := bufio.NewReaderSize(tr, 16<<10)
	res, err := authenticate(nc, r, opt.uid, opt.UnixFD && unixFDSupported)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	tr.acceptFDs = res.unixFD
	c := &Conn{
		nc: nc, tr: tr, r: r, unixFD: res.unixFD,
		pending: map[uint32]chan *Message{},
		subs:    map[int]*Subscription{},
		objects: map[ObjectPath]map[string]*Interface{},
		done:    make(chan struct{}),
		calls:   make(chan *Message, callQueue),
	}
	go c.readLoop()
	go c.callLoop()
	return c, nil
}

func (c *Conn) hello(ctx context.Context) error {
	m, err := c.Call(ctx, BusName, BusPath, BusInterface, "Hello", "")
	if err != nil {
		return err
	}
	if len(m.Body) != 1 {
		return malformed("Hello yanıtı")
	}
	name, ok := m.Body[0].(string)
	if !ok || !ValidBusName(name) || name[0] != ':' {
		return malformed("Hello yanıtı")
	}
	c.mu.Lock()
	c.name = name
	c.mu.Unlock()
	return nil
}

// UniqueName is the connection's name on the bus (":1.42").
func (c *Conn) UniqueName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.name
}

// UnixFD reports whether the bus passes file descriptors.
func (c *Conn) UnixFD() bool { return c.unixFD }

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err is why the connection ended (nil while open).
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close ends the connection; waiting calls fail with ErrClosed.
func (c *Conn) Close() error {
	c.fail(ErrClosed)
	return nil
}

func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = err
	pending := c.pending
	c.pending = map[uint32]chan *Message{}
	subs := c.subs
	c.subs = map[int]*Subscription{}
	c.mu.Unlock()
	_ = c.nc.Close()
	for _, ch := range pending {
		close(ch)
	}
	for _, s := range subs {
		s.closeLocal()
	}
	close(c.done)
	c.tr.closeQueued()
}

func (c *Conn) nextSerial() uint32 {
	for {
		s := c.serial.Add(1)
		if s != 0 {
			return s
		}
	}
}

func (c *Conn) send(m *Message) error {
	data, err := m.marshal()
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	_ = c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.nc.Write(data); err != nil {
		c.fail(fmt.Errorf("dbus: yazma: %w", err))
		return ErrClosed
	}
	return nil
}

// Call is one method call.
type Call struct {
	Destination string
	Path        ObjectPath
	Interface   string
	Member      string
	Signature   Signature
	Args        []any
	Flags       byte
}

// Call calls a method and waits for its reply. An ERROR reply is
// returned as *Error.
func (c *Conn) Call(ctx context.Context, dest string, path ObjectPath, iface, member string, sig Signature, args ...any) (*Message, error) {
	return c.Do(ctx, Call{Destination: dest, Path: path, Interface: iface, Member: member, Signature: sig, Args: args})
}

// Do sends a call and waits for its reply; with FlagNoReplyExpected it
// returns once the call is sent.
func (c *Conn) Do(ctx context.Context, call Call) (*Message, error) {
	m := &Message{
		Type: TypeMethodCall, Flags: call.Flags, Serial: c.nextSerial(),
		Destination: call.Destination, Path: call.Path, Interface: call.Interface,
		Member: call.Member, Signature: call.Signature, Body: call.Args,
	}
	if call.Flags&FlagNoReplyExpected != 0 {
		return nil, c.send(m)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCallTimeout)
		defer cancel()
	}
	ch := make(chan *Message, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if len(c.pending) >= maxPending {
		c.mu.Unlock()
		return nil, errors.New("dbus: çok fazla bekleyen çağrı")
	}
	c.pending[m.Serial] = ch
	c.mu.Unlock()
	if err := c.send(m); err != nil {
		c.dropPending(m.Serial)
		return nil, err
	}
	select {
	case reply, ok := <-ch:
		if !ok {
			return nil, ErrClosed
		}
		if reply.Type == TypeError {
			reply.CloseFiles()
			e := &Error{Name: reply.ErrorName, Body: reply.Body}
			if len(reply.Body) > 0 {
				if s, ok := reply.Body[0].(string); ok {
					e.Message = s
				}
			}
			return nil, e
		}
		return reply, nil
	case <-ctx.Done():
		c.dropPending(m.Serial)
		return nil, ctx.Err()
	}
}

func (c *Conn) dropPending(serial uint32) {
	c.mu.Lock()
	ch, ok := c.pending[serial]
	delete(c.pending, serial)
	c.mu.Unlock()
	if ok {
		// A reply that raced in is dropped with its descriptors.
		select {
		case m := <-ch:
			if m != nil {
				m.CloseFiles()
			}
		default:
		}
	}
}

// Emit sends a signal.
func (c *Conn) Emit(path ObjectPath, iface, member string, sig Signature, args ...any) error {
	return c.send(&Message{
		Type: TypeSignal, Serial: c.nextSerial(), Path: path,
		Interface: iface, Member: member, Signature: sig, Body: args,
	})
}

func (c *Conn) readLoop() {
	for {
		m, err := readMessage(c.r)
		if err != nil {
			c.fail(err)
			return
		}
		if m.UnixFDs > 0 {
			files, err := c.tr.takeFDs(int(m.UnixFDs))
			if err != nil {
				c.fail(err)
				return
			}
			m.Files = files
			if err := checkFDIndexes(m); err != nil {
				m.CloseFiles()
				c.fail(err)
				return
			}
		}
		c.dispatch(m)
	}
}

// checkFDIndexes makes sure every "h" value points into Files.
func checkFDIndexes(m *Message) error {
	var bad bool
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case UnixFD:
			if int(x) >= len(m.Files) {
				bad = true
			}
		case Variant:
			walk(x.Value)
		case Struct:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case []DictEntry:
			for _, e := range x {
				walk(e.Key)
				walk(e.Value)
			}
		}
	}
	for _, v := range m.Body {
		walk(v)
	}
	if bad {
		return malformed("dosya tanımlayıcısı dizini dışarıda")
	}
	return nil
}

func (c *Conn) dispatch(m *Message) {
	switch m.Type {
	case TypeMethodReturn, TypeError:
		c.mu.Lock()
		ch, ok := c.pending[m.ReplySerial]
		delete(c.pending, m.ReplySerial)
		c.mu.Unlock()
		if !ok {
			m.CloseFiles()
			return
		}
		ch <- m
	case TypeSignal:
		m.CloseFiles()
		c.mu.Lock()
		var targets []*Subscription
		for _, s := range c.subs {
			if s.match.matches(m) {
				targets = append(targets, s)
			}
		}
		c.mu.Unlock()
		for _, s := range targets {
			s.deliver(m)
		}
	case TypeMethodCall:
		m.CloseFiles()
		select {
		case c.calls <- m:
		default:
			c.replyError(m, ErrNameLimitsExceeded, "too many calls")
		}
	}
}

func (c *Conn) callLoop() {
	for {
		select {
		case <-c.done:
			return
		case m := <-c.calls:
			c.handleCall(m)
		}
	}
}

// Reply sends a method return for call.
func (c *Conn) reply(call *Message, sig Signature, body []any) error {
	if call.Flags&FlagNoReplyExpected != 0 {
		return nil
	}
	return c.send(&Message{
		Type: TypeMethodReturn, Serial: c.nextSerial(), ReplySerial: call.Serial,
		Destination: call.Sender, Signature: sig, Body: body,
	})
}

func (c *Conn) replyError(call *Message, name, msg string) {
	if call.Flags&FlagNoReplyExpected != 0 {
		return
	}
	_ = c.send(&Message{
		Type: TypeError, Serial: c.nextSerial(), ReplySerial: call.Serial,
		Destination: call.Sender, ErrorName: name, Signature: "s", Body: []any{msg},
	})
}

// Match selects signals. Empty fields match anything. Sender is put into
// the bus rule; locally it is compared only when it is a unique name,
// because signals always carry the sender's unique name.
type Match struct {
	Sender    string
	Path      ObjectPath
	Interface string
	Member    string
	// Arg0 matches the first string argument (NameOwnerChanged).
	Arg0 string
}

func (m Match) rule() string {
	parts := []string{"type='signal'"}
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"='"+v+"'")
		}
	}
	add("sender", m.Sender)
	add("path", string(m.Path))
	add("interface", m.Interface)
	add("member", m.Member)
	add("arg0", m.Arg0)
	return strings.Join(parts, ",")
}

func (m Match) valid() bool {
	ok := func(v string, f func(string) bool) bool { return v == "" || f(v) }
	return ok(m.Sender, ValidBusName) && ok(string(m.Path), ValidObjectPath) &&
		ok(m.Interface, ValidInterfaceName) && ok(m.Member, ValidMemberName) &&
		(m.Arg0 == "" || (ValidBusName(m.Arg0) && !strings.ContainsAny(m.Arg0, "'\\,")))
}

func (m Match) matches(msg *Message) bool {
	if m.Sender != "" && m.Sender[0] == ':' && msg.Sender != m.Sender {
		return false
	}
	if m.Path != "" && msg.Path != m.Path {
		return false
	}
	if m.Interface != "" && msg.Interface != m.Interface {
		return false
	}
	if m.Member != "" && msg.Member != m.Member {
		return false
	}
	if m.Arg0 != "" {
		if len(msg.Body) == 0 {
			return false
		}
		if s, ok := msg.Body[0].(string); !ok || s != m.Arg0 {
			return false
		}
	}
	return true
}

// Subscription receives matching signals. Signals that arrive while C is
// full are dropped (Dropped counts them).
type Subscription struct {
	C       <-chan *Message
	ch      chan *Message
	conn    *Conn
	id      int
	match   Match
	dropped atomic.Int64
	onBus   bool

	mu     sync.Mutex
	closed bool
}

func (s *Subscription) deliver(m *Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- m:
	default:
		s.dropped.Add(1)
	}
}

// Dropped is the number of signals lost to a full channel.
func (s *Subscription) Dropped() int64 { return s.dropped.Load() }

func (s *Subscription) closeLocal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

// Close stops the subscription and removes its bus rule.
func (s *Subscription) Close() {
	c := s.conn
	c.mu.Lock()
	_, ok := c.subs[s.id]
	delete(c.subs, s.id)
	closed := c.closed
	c.mu.Unlock()
	if ok {
		s.closeLocal()
	}
	if ok && !closed && s.onBus {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = c.Call(ctx, BusName, BusPath, BusInterface, "RemoveMatch", "s", s.match.rule())
	}
}

// Subscribe adds a match rule on the bus and returns the matching
// signals; buf is the channel size.
func (c *Conn) Subscribe(ctx context.Context, m Match, buf int) (*Subscription, error) {
	if !m.valid() {
		return nil, fmt.Errorf("%w: geçersiz eşleşme kuralı", ErrValue)
	}
	if buf < 1 {
		buf = 1
	}
	ch := make(chan *Message, buf)
	s := &Subscription{C: ch, ch: ch, conn: c, match: m}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if len(c.subs) >= maxSubscriptions {
		c.mu.Unlock()
		return nil, errors.New("dbus: çok fazla abonelik")
	}
	c.nextSub++
	s.id = c.nextSub
	c.subs[s.id] = s
	c.mu.Unlock()
	if _, err := c.Call(ctx, BusName, BusPath, BusInterface, "AddMatch", "s", m.rule()); err != nil {
		s.Close()
		return nil, err
	}
	s.onBus = true
	return s, nil
}

// Name request flags and replies (org.freedesktop.DBus.RequestName).
const (
	NameFlagAllowReplacement = 0x1
	NameFlagReplaceExisting  = 0x2
	NameFlagDoNotQueue       = 0x4

	NameReplyPrimaryOwner = 1
	NameReplyInQueue      = 2
	NameReplyExists       = 3
	NameReplyAlreadyOwner = 4
)

// RequestName asks the bus for a well-known name.
func (c *Conn) RequestName(ctx context.Context, name string, flags uint32) (uint32, error) {
	if !ValidBusName(name) || name[0] == ':' {
		return 0, fmt.Errorf("%w: geçersiz ad %q", ErrValue, name)
	}
	m, err := c.Call(ctx, BusName, BusPath, BusInterface, "RequestName", "su", name, flags)
	if err != nil {
		return 0, err
	}
	if len(m.Body) != 1 {
		return 0, malformed("RequestName yanıtı")
	}
	v, ok := m.Body[0].(uint32)
	if !ok {
		return 0, malformed("RequestName yanıtı")
	}
	return v, nil
}

// NameOwner returns the unique name that owns name.
func (c *Conn) NameOwner(ctx context.Context, name string) (string, error) {
	m, err := c.Call(ctx, BusName, BusPath, BusInterface, "GetNameOwner", "s", name)
	if err != nil {
		return "", err
	}
	if len(m.Body) != 1 {
		return "", malformed("GetNameOwner yanıtı")
	}
	s, ok := m.Body[0].(string)
	if !ok || !ValidBusName(s) || s[0] != ':' {
		return "", malformed("GetNameOwner yanıtı")
	}
	return s, nil
}
