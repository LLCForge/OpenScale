package mqttpub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBroker accepts one client on loopback, checks CONNECT and records
// the PUBLISH packets.
type fakeBroker struct {
	ln       net.Listener
	connect  chan []byte
	publish  chan [2]string // topic, payload; retain marked with "R:" prefix
	refuse   byte
	accepted chan struct{}
}

func newFakeBroker(t *testing.T, refuse byte) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") // loopback only
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{ln: ln, connect: make(chan []byte, 1), publish: make(chan [2]string, 16), refuse: refuse, accepted: make(chan struct{})}
	t.Cleanup(func() { ln.Close() })
	go b.serve()
	return b
}

func (b *fakeBroker) serve() {
	c, err := b.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	close(b.accepted)
	r := bufio.NewReader(c)
	typ, _, body, err := readPacket(r, 64<<10)
	if err != nil || typ != typeConnect {
		return
	}
	b.connect <- body
	if _, err := c.Write([]byte{typeConnack << 4, 2, 0, b.refuse}); err != nil || b.refuse != 0 {
		return
	}
	for {
		typ, flags, body, err := readPacket(r, 64<<10)
		if err != nil {
			return
		}
		switch typ {
		case typePublish:
			n := int(binary.BigEndian.Uint16(body))
			topic := string(body[2 : 2+n])
			if flags&1 == 1 {
				topic = "R:" + topic
			}
			b.publish <- [2]string{topic, string(body[2+n:])}
		case typePingreq:
			_, _ = c.Write([]byte{typePingresp << 4, 0})
		case typeDisconnect:
			return
		}
	}
}

func testConfig(t *testing.T, addr string) *Config {
	c, err := NewConfig(addr, "ev/openscale", "ali", "gizli-parola", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConnectPublish(t *testing.T) {
	b := newFakeBroker(t, 0)
	c := testConfig(t, b.ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, err := Connect(ctx, c, "Ali's Laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := <-b.connect
	// Protocol name, level 4, flags: user, password, will retain, will, clean.
	if !bytes.HasPrefix(body, []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 0x80 | 0x40 | 0x20 | 0x04 | 0x02}) {
		t.Fatalf("connect header % x", body[:8])
	}
	if !bytes.Contains(body, []byte("ev/openscale/ali_s_laptop/availability")) || !bytes.Contains(body, []byte("offline")) || !bytes.Contains(body, []byte("gizli-parola")) {
		t.Fatal("connect payload")
	}
	topics := TopicsFor(c, "Ali's Laptop")
	if err := cl.Publish(topics.Availability, []byte("online"), true); err != nil {
		t.Fatal(err)
	}
	payload, _ := Event{Kind: "device_added", Category: "security", Message: strings.Repeat("x", 10000)}.Encode()
	if err := cl.Publish(topics.Event, payload, false); err != nil {
		t.Fatal(err)
	}
	if got := <-b.publish; got[0] != "R:ev/openscale/ali_s_laptop/availability" || got[1] != "online" {
		t.Fatalf("retained publish %v", got)
	}
	if got := <-b.publish; got[0] != topics.Event || len(got[1]) > maxMessage || !strings.Contains(got[1], `"kind":"device_added"`) {
		t.Fatalf("event publish %q", got[0])
	}
	if err := cl.Publish("a/+/b", nil, false); err == nil {
		t.Fatal("wildcard topic published")
	}
	if err := cl.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectRefused(t *testing.T) {
	b := newFakeBroker(t, 4)
	c := testConfig(t, b.ln.Addr().String())
	_, err := Connect(context.Background(), c, "nas", nil)
	if err == nil || !strings.Contains(err.Error(), "parolası yanlış") {
		t.Fatalf("refused: %v", err)
	}
}

func TestDestinationRule(t *testing.T) {
	c := testConfig(t, "203.0.113.5:1883") // documentation range, public
	if _, err := Connect(context.Background(), c, "nas", nil); !errors.Is(err, ErrDestination) {
		t.Fatalf("public broker: %v", err)
	}
}

func TestConfigValidateAndSave(t *testing.T) {
	bad := []Config{
		{Schema: 1, Broker: "x", Prefix: "p", ClientID: "c"},
		{Schema: 1, Broker: "h:0", Prefix: "p", ClientID: "c"},
		{Schema: 1, Broker: "h:1883", Prefix: "p/#", ClientID: "c"},
		{Schema: 1, Broker: "h:1883", Prefix: "$SYS", ClientID: "c"},
		{Schema: 1, Broker: "h:1883", Prefix: "p", ClientID: strings.Repeat("c", 24)},
		{Schema: 1, Broker: "h:1883", Prefix: "p", ClientID: "c", Password: "x"},
		{Schema: 2, Broker: "h:1883", Prefix: "p", ClientID: "c"},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("bad config %d accepted", i)
		}
	}
	c, err := NewConfig("192.168.1.10", "", "", "", []string{"security"}, nil)
	if err != nil || c.Broker != "192.168.1.10:1883" || c.Prefix != DefaultPrefix {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if !c.Wants("x", "security") || c.Wants("x", "connection") {
		t.Fatal("event filter")
	}
	path := filepath.Join(t.TempDir(), ConfigFile)
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil || back.ClientID != c.ClientID {
		t.Fatalf("load: %v", err)
	}
}

func TestReadPacketBounds(t *testing.T) {
	// A remaining length longer than four bytes is malformed.
	r := bufio.NewReader(bytes.NewReader([]byte{0x20, 0xff, 0xff, 0xff, 0xff, 0x01}))
	if _, _, _, err := readPacket(r, maxIncoming); !errors.Is(err, errMalformed) {
		t.Fatalf("long length: %v", err)
	}
	// A packet over the incoming limit is refused before reading it.
	big := appendRemaining([]byte{0x30}, maxIncoming+1)
	if _, _, _, err := readPacket(bufio.NewReader(bytes.NewReader(big)), maxIncoming); !errors.Is(err, errMalformed) {
		t.Fatalf("big: %v", err)
	}
	if got := appendRemaining(nil, 321); !bytes.Equal(got, []byte{0xC1, 0x02}) {
		t.Fatalf("remaining length % x", got)
	}
}
