package dbuswire

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBus is the bus end of a net.Pipe: it authenticates, answers Hello,
// AddMatch and RemoveMatch, and hands every other message to the test.
type fakeBus struct {
	t      *testing.T
	c      net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	serial atomic.Uint32
	in     chan *Message
	rules  chan string
}

func newFakeBus(t *testing.T) (*Conn, *fakeBus) {
	t.Helper()
	client, server := net.Pipe()
	fb := &fakeBus{t: t, c: server, r: bufio.NewReader(server), in: make(chan *Message, 16), rules: make(chan string, 16)}
	ready := make(chan error, 1)
	go func() { ready <- fb.auth() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := newConn(ctx, client, Options{uid: "1000"})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := <-ready; err != nil {
		t.Fatalf("bus auth: %v", err)
	}
	go fb.loop()
	if err := conn.hello(ctx); err != nil {
		t.Fatalf("hello: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Close()
	})
	return conn, fb
}

func (fb *fakeBus) auth() error {
	nul, err := fb.r.ReadByte()
	if err != nil || nul != 0 {
		return errors.New("NUL yok")
	}
	line, err := fb.r.ReadString('\n')
	if err != nil {
		return err
	}
	if line != "AUTH EXTERNAL 31303030\r\n" {
		return errors.New("AUTH satırı: " + line)
	}
	if _, err := fb.c.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n")); err != nil {
		return err
	}
	line, err = fb.r.ReadString('\n')
	if err != nil || line != "BEGIN\r\n" {
		return errors.New("BEGIN yok")
	}
	return nil
}

func (fb *fakeBus) send(m *Message) {
	if m.Serial == 0 {
		m.Serial = fb.serial.Add(1)
	}
	data, err := m.marshal()
	if err != nil {
		fb.t.Errorf("fake bus marshal: %v", err)
		return
	}
	fb.wmu.Lock()
	defer fb.wmu.Unlock()
	_, _ = fb.c.Write(data)
}

func (fb *fakeBus) loop() {
	for {
		m, err := readMessage(fb.r)
		if err != nil {
			return
		}
		if m.Type == TypeMethodCall && m.Destination == BusName {
			reply := &Message{Type: TypeMethodReturn, ReplySerial: m.Serial, Destination: ":1.7", Sender: BusName}
			switch m.Member {
			case "Hello":
				reply.Signature, reply.Body = "s", []any{":1.7"}
			case "AddMatch", "RemoveMatch":
				fb.rules <- m.Member + " " + m.Body[0].(string)
			case "RequestName":
				reply.Signature, reply.Body = "u", []any{uint32(NameReplyPrimaryOwner)}
			case "GetNameOwner":
				reply.Signature, reply.Body = "s", []any{":1.99"}
			default:
				reply = &Message{Type: TypeError, ReplySerial: m.Serial, ErrorName: ErrNameUnknownMethod, Signature: "s", Body: []any{"nope"}}
			}
			fb.send(reply)
			continue
		}
		fb.in <- m
	}
}

func (fb *fakeBus) next(t *testing.T) *Message {
	t.Helper()
	select {
	case m := <-fb.in:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("bus: ileti gelmedi")
		return nil
	}
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCallReplyAndError(t *testing.T) {
	conn, fb := newFakeBus(t)
	if conn.UniqueName() != ":1.7" {
		t.Fatalf("name %q", conn.UniqueName())
	}
	done := make(chan error, 2)
	go func() {
		m, err := conn.Call(ctx5(t), "org.example.Svc", "/obj", "org.example.Iface", "Echo", "s", "hey")
		if err == nil && (len(m.Body) != 1 || m.Body[0] != "HEY") {
			err = errors.New("yanıt yanlış")
		}
		done <- err
	}()
	call := fb.next(t)
	if call.Member != "Echo" || call.Body[0] != "hey" || call.Destination != "org.example.Svc" {
		t.Fatalf("%+v", call)
	}
	fb.send(&Message{Type: TypeMethodReturn, ReplySerial: call.Serial, Signature: "s", Body: []any{"HEY"}})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := conn.Call(ctx5(t), "org.example.Svc", "/obj", "org.example.Iface", "Fail", "")
		done <- err
	}()
	call = fb.next(t)
	fb.send(&Message{Type: TypeError, ReplySerial: call.Serial, ErrorName: "org.example.Error.Nope", Signature: "s", Body: []any{"hayır"}})
	err := <-done
	var de *Error
	if !errors.As(err, &de) || de.Name != "org.example.Error.Nope" || de.Message != "hayır" {
		t.Fatalf("%v", err)
	}
}

func TestCallTimeoutAndClose(t *testing.T) {
	conn, fb := newFakeBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	go func() { _ = fb.next(t) }()
	if _, err := conn.Call(ctx, "org.example.Svc", "/obj", "org.example.Iface", "Slow", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Call(ctx5(t), "org.example.Svc", "/obj", "org.example.Iface", "Never", "")
		errc <- err
	}()
	_ = fb.next(t)
	_ = conn.Close()
	if err := <-errc; !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	<-conn.Done()
}

func TestSubscribe(t *testing.T) {
	conn, fb := newFakeBus(t)
	sub, err := conn.Subscribe(ctx5(t), Match{Sender: ":1.99", Path: "/req/1", Interface: "org.freedesktop.portal.Request", Member: "Response"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if r := <-fb.rules; !strings.Contains(r, "AddMatch type='signal',sender=':1.99',path='/req/1'") {
		t.Fatalf("rule %q", r)
	}
	// Another sender with the same path is not delivered.
	fb.send(&Message{Type: TypeSignal, Sender: ":1.50", Path: "/req/1", Interface: "org.freedesktop.portal.Request", Member: "Response", Signature: "u", Body: []any{uint32(9)}})
	fb.send(&Message{Type: TypeSignal, Sender: ":1.99", Path: "/req/1", Interface: "org.freedesktop.portal.Request", Member: "Response", Signature: "u", Body: []any{uint32(0)}})
	select {
	case m := <-sub.C:
		if m.Body[0] != uint32(0) {
			t.Fatalf("yanlış sinyal %v", m.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sinyal gelmedi")
	}
	sub.Close()
	if r := <-fb.rules; !strings.HasPrefix(r, "RemoveMatch ") {
		t.Fatalf("rule %q", r)
	}
	if _, err := conn.Subscribe(ctx5(t), Match{Arg0: "x',y"}, 1); err == nil {
		t.Fatal("geçersiz kural kabul edildi")
	}
}

func TestExportedObject(t *testing.T) {
	conn, fb := newFakeBus(t)
	var clicks atomic.Int32
	err := conn.Export("/MenuBar", &Interface{
		Name: "com.example.Menu",
		Methods: []Method{{
			Name: "Event", In: "is", Out: "",
			Handler: func(c *MethodCall) ([]any, error) {
				if c.Sender != ":1.20" {
					return nil, errors.New("gönderen")
				}
				clicks.Add(1)
				return nil, nil
			},
		}, {
			Name: "Boom", Handler: func(*MethodCall) ([]any, error) { panic("x") },
		}, {
			Name: "Secret", Handler: func(*MethodCall) ([]any, error) { return nil, errors.New("iç ayrıntı /etc/x") },
		}},
		Properties: []Property{{Name: "Version", Sig: "u", Get: func() any { return uint32(3) }}},
		Signals:    []SignalDef{{Name: "LayoutUpdated", Sig: "ui"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path ObjectPath, iface, member string, sig Signature, args ...any) *Message {
		fb.send(&Message{Type: TypeMethodCall, Sender: ":1.20", Destination: ":1.7", Path: path, Interface: iface, Member: member, Signature: sig, Body: args})
		return fb.next(t)
	}
	if r := call("/MenuBar", "com.example.Menu", "Event", "is", int32(1), "clicked"); r.Type != TypeMethodReturn || clicks.Load() != 1 {
		t.Fatalf("%+v", r)
	}
	if r := call("/MenuBar", "com.example.Menu", "Event", "s", "x"); r.ErrorName != ErrNameInvalidArgs {
		t.Fatalf("%+v", r)
	}
	if r := call("/MenuBar", "com.example.Menu", "Nope", ""); r.ErrorName != ErrNameUnknownMethod {
		t.Fatalf("%+v", r)
	}
	if r := call("/Other", "com.example.Menu", "Event", "is", int32(1), "x"); r.ErrorName != ErrNameUnknownObject {
		t.Fatalf("%+v", r)
	}
	if r := call("/MenuBar", "com.example.Menu", "Boom", ""); r.ErrorName != ErrNameFailed {
		t.Fatalf("%+v", r)
	}
	if r := call("/MenuBar", "com.example.Menu", "Secret", ""); r.ErrorName != ErrNameFailed || strings.Contains(r.Body[0].(string), "/etc") {
		t.Fatalf("iç hata sızdı: %+v", r)
	}
	r := call("/MenuBar", PropertiesInterface, "GetAll", "s", "com.example.Menu")
	if r.Signature != "a{sv}" || r.Body[0].([]DictEntry)[0].Value.(Variant).Value != uint32(3) {
		t.Fatalf("%+v", r)
	}
	r = call("/MenuBar", PropertiesInterface, "Get", "ss", "com.example.Menu", "Version")
	if r.Body[0].(Variant).Value != uint32(3) {
		t.Fatalf("%+v", r)
	}
	if r := call("/MenuBar", PropertiesInterface, "Set", "ssv", "com.example.Menu", "Version", MakeVariant(uint32(1))); r.ErrorName != ErrNameReadOnly {
		t.Fatalf("%+v", r)
	}
	r = call("/MenuBar", IntrospectableInterface, "Introspect", "")
	xml := r.Body[0].(string)
	for _, want := range []string{`<interface name="com.example.Menu">`, `<arg type="i" direction="in"/>`, `<property name="Version" type="u" access="read"/>`, `<signal name="LayoutUpdated">`} {
		if !strings.Contains(xml, want) {
			t.Errorf("introspection: %q yok\n%s", want, xml)
		}
	}
	r = call("/", IntrospectableInterface, "Introspect", "")
	if !strings.Contains(r.Body[0].(string), `<node name="MenuBar"/>`) {
		t.Errorf("kök düğüm: %s", r.Body[0])
	}
	// No reply expected: nothing comes back, the next reply is Ping's.
	fb.send(&Message{Type: TypeMethodCall, Flags: FlagNoReplyExpected, Sender: ":1.20", Path: "/MenuBar", Interface: "com.example.Menu", Member: "Event", Signature: "is", Body: []any{int32(2), "x"}})
	if r := call("/MenuBar", PeerInterface, "Ping", ""); r.Type != TypeMethodReturn || clicks.Load() != 2 {
		t.Fatalf("%+v clicks=%d", r, clicks.Load())
	}
	if err := conn.Emit("/MenuBar", "com.example.Menu", "LayoutUpdated", "ui", uint32(1), int32(0)); err != nil {
		t.Fatal(err)
	}
	if s := fb.next(t); s.Type != TypeSignal || s.Member != "LayoutUpdated" {
		t.Fatalf("%+v", s)
	}
}

func TestRequestNameAndOwner(t *testing.T) {
	conn, _ := newFakeBus(t)
	r, err := conn.RequestName(ctx5(t), "org.kde.StatusNotifierItem-1-1", NameFlagDoNotQueue)
	if err != nil || r != NameReplyPrimaryOwner {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := conn.RequestName(ctx5(t), ":1.5", 0); err == nil {
		t.Fatal("eşsiz ad istendi")
	}
	if o, err := conn.NameOwner(ctx5(t), "org.freedesktop.portal.Desktop"); err != nil || o != ":1.99" {
		t.Fatalf("%v %v", o, err)
	}
}

func TestMalformedClosesConnection(t *testing.T) {
	conn, fb := newFakeBus(t)
	fb.wmu.Lock()
	_, _ = fb.c.Write([]byte("lXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"))
	fb.wmu.Unlock()
	select {
	case <-conn.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("bozuk ileti bağlantıyı kapatmadı")
	}
	if !errors.Is(conn.Err(), ErrMalformed) {
		t.Fatalf("%v", conn.Err())
	}
}

func TestAuthRejected(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		r := bufio.NewReader(server)
		_, _ = r.ReadByte()
		_, _ = r.ReadString('\n')
		_, _ = server.Write([]byte("REJECTED EXTERNAL\r\n"))
	}()
	if _, err := newConn(ctx5(t), client, Options{uid: "1000"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("%v", err)
	}
	client2, server2 := net.Pipe()
	defer server2.Close()
	go func() {
		r := bufio.NewReader(server2)
		_, _ = r.ReadByte()
		_, _ = r.ReadString('\n')
		_, _ = server2.Write([]byte(strings.Repeat("A", 2000) + "\r\n"))
	}()
	if _, err := newConn(ctx5(t), client2, Options{uid: "1000"}); err == nil {
		t.Fatal("uzun satır kabul edildi")
	}
	if _, err := newConn(ctx5(t), client2, Options{uid: "-1"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("uid: %v", err)
	}
}
