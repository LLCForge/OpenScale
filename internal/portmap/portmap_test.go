package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every test talks to fake gateways on 127.0.0.1 only; nothing is sent to
// a real router and multicast discovery is off.

var (
	loopback = netip.MustParseAddr("127.0.0.1")
	publicIP = netip.MustParseAddr("203.0.113.7")
)

const testPort = 51820

func testOptions(pcp, ssdp int) Options {
	return Options{pcpPort: pcp, ssdpPort: ssdp, noMulticast: true, allowLoopback: true,
		retries: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}}
}

// fakePMP is a PCP and NAT-PMP gateway on 127.0.0.1.
type fakePMP struct {
	t       *testing.T
	pc      *net.UDPConn
	natOnly bool // answers PCP with NAT-PMP "unsupported version"
	noPCP   bool // ignores PCP entirely
	noNAT   bool // ignores NAT-PMP entirely

	mu       sync.Mutex
	ext      netip.Addr
	start    time.Time         // epoch start
	maps     map[uint16]uint16 // internal -> external
	deletes  int
	requests int
}

func newFakePMP(t *testing.T) *fakePMP {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePMP{t: t, pc: pc, ext: publicIP, start: time.Now(), maps: map[uint16]uint16{}}
	t.Cleanup(func() { _ = pc.Close() })
	go f.serve()
	return f
}

func (f *fakePMP) port() int { return f.pc.LocalAddr().(*net.UDPAddr).Port }

// reboot loses every mapping and restarts the epoch.
func (f *fakePMP) reboot() {
	f.mu.Lock()
	f.start = time.Now()
	f.maps = map[uint16]uint16{}
	f.mu.Unlock()
}

func (f *fakePMP) epoch() uint32 { return uint32(time.Since(f.start)/time.Second) + 0 }

func (f *fakePMP) serve() {
	buf := make([]byte, 1200)
	for {
		n, from, err := f.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		f.mu.Lock()
		f.requests++
		reply := f.handle(req)
		f.mu.Unlock()
		if reply != nil {
			_, _ = f.pc.WriteToUDPAddrPort(reply, from)
		}
	}
}

func (f *fakePMP) handle(req []byte) []byte {
	if len(req) < 2 {
		return nil
	}
	switch req[0] {
	case pcpVersion:
		if f.noPCP {
			return nil
		}
		if f.natOnly {
			r := make([]byte, 8)
			r[0], r[1] = 0, req[1]|natpmpResponseBit
			binary.BigEndian.PutUint16(r[2:4], natpmpUnsupportedVersion)
			binary.BigEndian.PutUint32(r[4:8], f.epoch())
			return r
		}
		return f.pcp(req)
	case natpmpVersion:
		if f.noNAT {
			return nil
		}
		return f.natpmp(req)
	}
	return nil
}

func (f *fakePMP) pcp(req []byte) []byte {
	if len(req) < pcpHeaderLen {
		return nil
	}
	op := req[1]
	resp := make([]byte, len(req))
	copy(resp, req)
	resp[1] = op | pcpResponseBit
	resp[2], resp[3] = 0, pcpSuccess
	binary.BigEndian.PutUint32(resp[8:12], f.epoch())
	clear(resp[12:24])
	if op == pcpOpAnnounce {
		binary.BigEndian.PutUint32(resp[4:8], 0)
		return resp[:pcpHeaderLen]
	}
	if op != pcpOpMap || len(req) < pcpHeaderLen+pcpMapLen {
		resp[3] = pcpMalformedRequest
		return resp
	}
	m := req[pcpHeaderLen:]
	internal := binary.BigEndian.Uint16(m[16:18])
	lifetime := binary.BigEndian.Uint32(req[4:8])
	out := resp[pcpHeaderLen:]
	if lifetime == 0 {
		delete(f.maps, internal)
		f.deletes++
		binary.BigEndian.PutUint32(resp[4:8], 0)
		return resp
	}
	ext, ok := f.maps[internal]
	if !ok {
		ext = 40000 + internal%1000
		f.maps[internal] = ext
	}
	binary.BigEndian.PutUint32(resp[4:8], min(lifetime, 3600))
	binary.BigEndian.PutUint16(out[18:20], ext)
	putAddr16(out[20:36], f.ext)
	return resp
}

func (f *fakePMP) natpmp(req []byte) []byte {
	switch req[1] {
	case natpmpOpExternal:
		r := make([]byte, 12)
		r[1] = natpmpOpExternal | natpmpResponseBit
		binary.BigEndian.PutUint32(r[4:8], f.epoch())
		a := f.ext.As4()
		copy(r[8:12], a[:])
		return r
	case natpmpOpMapUDP:
		if len(req) < 12 {
			return nil
		}
		internal := binary.BigEndian.Uint16(req[4:6])
		lifetime := binary.BigEndian.Uint32(req[8:12])
		r := make([]byte, 16)
		r[1] = natpmpOpMapUDP | natpmpResponseBit
		binary.BigEndian.PutUint32(r[4:8], f.epoch())
		binary.BigEndian.PutUint16(r[8:10], internal)
		if lifetime == 0 {
			delete(f.maps, internal)
			f.deletes++
			return r
		}
		ext, ok := f.maps[internal]
		if !ok {
			ext = 41000 + internal%1000
			f.maps[internal] = ext
		}
		binary.BigEndian.PutUint16(r[10:12], ext)
		binary.BigEndian.PutUint32(r[12:16], min(lifetime, 3600))
		return r
	}
	return nil
}

func (f *fakePMP) state() (maps int, deletes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.maps), f.deletes
}

func newClient(t *testing.T, opts Options) *Client {
	t.Helper()
	c, err := New(loopback, loopback, testPort, opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPCPMapRenewDelete(t *testing.T) {
	f := newFakePMP(t)
	c := newClient(t, testOptions(f.port(), 1))
	ctx := context.Background()
	m, err := c.Map(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Protocol != ProtoPCP || m.External != netip.AddrPortFrom(publicIP, 40000+testPort%1000) || m.Lifetime != time.Hour {
		t.Fatalf("mapping %+v", m)
	}
	if got := m.RenewAt().Sub(m.Obtained); got != 30*time.Minute {
		t.Fatalf("renew after %s, want half the lifetime", got)
	}
	m2, err := c.Map(ctx)
	if err != nil || m2.External != m.External {
		t.Fatalf("renewal: %+v, %v", m2, err)
	}
	if lost, changed, err := c.Check(ctx); err != nil || lost || changed {
		t.Fatalf("check: lost %v changed %v err %v", lost, changed, err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if n, d := f.state(); n != 0 || d != 1 {
		t.Fatalf("after close: %d mappings, %d deletes", n, d)
	}
	if _, ok := c.Current(); ok {
		t.Fatal("mapping kept after close")
	}
}

func TestNATPMPFallbackFromPCP(t *testing.T) {
	f := newFakePMP(t)
	f.natOnly = true
	c := newClient(t, testOptions(f.port(), 1))
	m, err := c.Map(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.Protocol != ProtoNATPMP || m.External != netip.AddrPortFrom(publicIP, 41000+testPort%1000) {
		t.Fatalf("mapping %+v", m)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, d := f.state(); n != 0 || d != 1 {
		t.Fatalf("after close: %d mappings, %d deletes", n, d)
	}
}

func TestDisabledProtocolsAreSkipped(t *testing.T) {
	f := newFakePMP(t)
	opts := testOptions(f.port(), 1)
	opts.DisablePCP = true
	c := newClient(t, opts)
	m, err := c.Map(context.Background())
	if err != nil || m.Protocol != ProtoNATPMP {
		t.Fatalf("mapping %+v, %v", m, err)
	}
	opts.DisableNATPMP, opts.DisableUPnP = true, true
	if _, err := New(loopback, loopback, testPort, opts); !errors.Is(err, ErrAllDisabled) {
		t.Fatalf("all disabled: %v", err)
	}
}

func TestDoubleNATIsRefusedAndDeleted(t *testing.T) {
	f := newFakePMP(t)
	f.ext = netip.MustParseAddr("100.64.1.2")
	opts := testOptions(f.port(), 1)
	opts.DisableUPnP = true
	c := newClient(t, opts)
	if _, err := c.Map(context.Background()); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("got %v, want ErrNotPublic", err)
	}
	if n, _ := f.state(); n != 0 {
		t.Fatalf("%d mappings left on the gateway", n)
	}
}

func TestGatewayMustBeLocal(t *testing.T) {
	for _, gw := range []string{"8.8.8.8", "127.0.0.1", "fd00::1"} {
		if _, err := New(netip.MustParseAddr(gw), netip.MustParseAddr("192.168.1.10"), testPort, Options{}); !errors.Is(err, ErrGatewayNotAllowed) {
			t.Errorf("gateway %s: %v", gw, err)
		}
	}
	for _, gw := range []string{"192.168.1.1", "10.0.0.1", "100.64.0.1", "169.254.1.1"} {
		if _, err := New(netip.MustParseAddr(gw), netip.MustParseAddr("192.168.1.10"), testPort, Options{}); err != nil {
			t.Errorf("gateway %s: %v", gw, err)
		}
	}
	if _, err := New(netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.10"), testPort, Options{Lifetime: time.Minute}); err == nil {
		t.Error("short lifetime accepted")
	}
	if _, err := New(netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.10"), testPort, Options{Description: "a\x00b"}); err == nil {
		t.Error("control character in description accepted")
	}
}

func TestNoReplyFromOtherAddress(t *testing.T) {
	// A gateway that answers from another port is ignored.
	f := newFakePMP(t)
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		buf := make([]byte, 1200)
		for {
			n, from, err := other.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			f.mu.Lock()
			reply := f.handle(buf[:n])
			f.mu.Unlock()
			// Answer from a third socket: wrong source port.
			s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return
			}
			_, _ = s.WriteToUDPAddrPort(reply, from)
			_ = s.Close()
		}
	}()
	opts := testOptions(other.LocalAddr().(*net.UDPAddr).Port, 1)
	opts.DisableUPnP = true
	c := newClient(t, opts)
	if _, err := c.Map(context.Background()); err == nil {
		t.Fatal("reply from a foreign port accepted")
	}
}

func TestRunRemapsAfterGatewayRestart(t *testing.T) {
	f := newFakePMP(t)
	opts := testOptions(f.port(), 1)
	opts.DisableUPnP = true
	opts.checkEvery = 50 * time.Millisecond
	opts.retryFirst = 50 * time.Millisecond
	// The fake's clock runs in seconds; let the client's clock run fast so
	// that a restart shows as server time lagging far behind.
	var skew atomic.Int64
	opts.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	c := newClient(t, opts)
	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan bool, 16)
	done := make(chan struct{})
	go func() {
		c.Run(ctx, func(m Mapping, ok bool) { changes <- ok })
		close(done)
	}()
	expect := func(want bool) {
		t.Helper()
		select {
		case ok := <-changes:
			if ok != want {
				t.Fatalf("change ok=%v, want %v", ok, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no change (want ok=%v)", want)
		}
	}
	expect(true)
	reqs := func() int { f.mu.Lock(); defer f.mu.Unlock(); return f.requests }
	// Gateway restart: mappings gone, epoch back to zero while the client
	// clock moved on by a minute.
	f.reboot()
	skew.Store(int64(time.Minute))
	before := reqs()
	waitUntil(t, func() bool {
		n, _ := f.state()
		return n == 1 && reqs() > before+1
	})
	if _, ok := c.Current(); !ok {
		t.Fatal("no mapping after the restart")
	}
	cancel()
	<-done
	if n, d := f.state(); n != 0 || d < 1 {
		t.Fatalf("after stop: %d mappings, %d deletes", n, d)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestEpoch(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	cases := []struct {
		name   string
		s0, s1 uint32
		dt     time.Duration
		reset  bool
	}{
		{"steady", 100, 160, time.Minute, false},
		{"reorder by one second", 100, 99, 0, false},
		{"backwards", 100, 10, time.Second, true},
		{"server lags (reboot)", 1000, 1010, time.Hour, true},
		{"server ahead", 1000, 5000, time.Minute, true},
		{"small drift", 1000, 4600, time.Hour, false},
	}
	for _, c := range cases {
		var e epochState
		e.observe(c.s0, t0)
		if got := e.observe(c.s1, t0.Add(c.dt)); got != c.reset {
			t.Errorf("%s: reset %v, want %v", c.name, got, c.reset)
		}
	}
}

// fakeIGD is a UPnP Internet Gateway Device on 127.0.0.1: an SSDP
// responder and an HTTP server with the description and SOAP control.
type fakeIGD struct {
	t        *testing.T
	ssdp     *net.UDPConn
	srv      *httptest.Server
	location string // overrides the LOCATION header when set

	permanentOnly bool
	conflictFirst bool

	mu       sync.Mutex
	maps     map[string]string // external port -> "client:port"
	lease    string
	deletes  int
	fetches  int
	actions  []string
	external string
}

func newFakeIGD(t *testing.T) *fakeIGD {
	f := &fakeIGD{t: t, maps: map[string]string{}, external: publicIP.String()}
	f.srv = httptest.NewServer(http.HandlerFunc(f.http))
	t.Cleanup(f.srv.Close)
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.ssdp = pc
	t.Cleanup(func() { _ = pc.Close() })
	go f.serveSSDP()
	return f
}

func (f *fakeIGD) ssdpPort() int { return f.ssdp.LocalAddr().(*net.UDPAddr).Port }

func (f *fakeIGD) serveSSDP() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.ssdp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if !strings.HasPrefix(string(buf[:n]), "M-SEARCH * HTTP/1.1\r\n") {
			continue
		}
		loc := f.location
		if loc == "" {
			loc = f.srv.URL + "/rootDesc.xml"
		}
		reply := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: " + loc + "\r\n\r\n"
		_, _ = f.ssdp.WriteToUDPAddrPort([]byte(reply), from)
	}
}

const testDescription = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/ctl/L3F</controlURL></service></serviceList>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
     <controlURL>/ctl/IPConn</controlURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`

func soapReply(action, inner string) string {
	return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:` + action +
		`Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` + inner + `</u:` + action + `Response></s:Body></s:Envelope>`
}

func soapFaultReply(code int, desc string) string {
	return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>` +
		strconv.Itoa(code) + `</errorCode><errorDescription>` + desc + `</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`
}

func xmlField(body, name string) string {
	i := strings.Index(body, "<"+name+">")
	j := strings.Index(body, "</"+name+">")
	if i < 0 || j < i {
		return ""
	}
	return body[i+len(name)+2 : j]
}

func (f *fakeIGD) http(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/rootDesc.xml":
		f.fetches++
		_, _ = io.WriteString(w, testDescription)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/ctl/IPConn":
	default:
		http.NotFound(w, r)
		return
	}
	b, _ := io.ReadAll(r.Body)
	body := string(b)
	action := strings.Trim(r.Header.Get("SOAPAction"), `"`)
	action = action[strings.LastIndex(action, "#")+1:]
	f.actions = append(f.actions, action)
	fault := func(code int, desc string) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, soapFaultReply(code, desc))
	}
	switch action {
	case "GetExternalIPAddress":
		_, _ = io.WriteString(w, soapReply(action, "<NewExternalIPAddress>"+f.external+"</NewExternalIPAddress>"))
	case "AddPortMapping":
		ext := xmlField(body, "NewExternalPort")
		lease := xmlField(body, "NewLeaseDuration")
		if f.permanentOnly && lease != "0" {
			fault(upnpOnlyPermanent, "OnlyPermanentLeasesSupported")
			return
		}
		if f.conflictFirst && ext == strconv.Itoa(testPort) {
			fault(upnpConflict, "ConflictInMappingEntry")
			return
		}
		f.maps[ext] = xmlField(body, "NewInternalClient") + ":" + xmlField(body, "NewInternalPort")
		f.lease = lease
		_, _ = io.WriteString(w, soapReply(action, ""))
	case "GetSpecificPortMappingEntry":
		v, ok := f.maps[xmlField(body, "NewExternalPort")]
		if !ok {
			fault(upnpNoSuchEntry, "NoSuchEntryInArray")
			return
		}
		host, port, _ := strings.Cut(v, ":")
		_, _ = io.WriteString(w, soapReply(action, "<NewInternalPort>"+port+"</NewInternalPort><NewInternalClient>"+host+
			"</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>OpenScale</NewPortMappingDescription><NewLeaseDuration>7200</NewLeaseDuration>"))
	case "DeletePortMapping":
		ext := xmlField(body, "NewExternalPort")
		if _, ok := f.maps[ext]; !ok {
			fault(upnpNoSuchEntry, "NoSuchEntryInArray")
			return
		}
		delete(f.maps, ext)
		f.deletes++
		_, _ = io.WriteString(w, soapReply(action, ""))
	default:
		fault(401, "Invalid Action")
	}
}

func upnpOptions(f *fakeIGD) Options {
	opts := testOptions(1, f.ssdpPort())
	opts.DisablePCP, opts.DisableNATPMP = true, true
	return opts
}

func TestUPnPMapCheckDelete(t *testing.T) {
	f := newFakeIGD(t)
	c := newClient(t, upnpOptions(f))
	ctx := context.Background()
	m, err := c.Map(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Protocol != ProtoUPnP || m.External != netip.AddrPortFrom(publicIP, testPort) || m.Lifetime != DefaultLifetime {
		t.Fatalf("mapping %+v", m)
	}
	f.mu.Lock()
	got, lease := f.maps[strconv.Itoa(testPort)], f.lease
	f.mu.Unlock()
	if got != "127.0.0.1:"+strconv.Itoa(testPort) || lease != "7200" {
		t.Fatalf("gateway has %q lease %q", got, lease)
	}
	if lost, changed, err := c.Check(ctx); err != nil || lost || changed {
		t.Fatalf("check: lost %v changed %v err %v", lost, changed, err)
	}
	// The external address changes.
	f.mu.Lock()
	f.external = "198.51.100.9"
	f.mu.Unlock()
	if lost, changed, err := c.Check(ctx); err != nil || lost || !changed {
		t.Fatalf("check after address change: lost %v changed %v err %v", lost, changed, err)
	}
	if cur, _ := c.Current(); cur.External.Addr() != netip.MustParseAddr("198.51.100.9") {
		t.Fatalf("external address not updated: %v", cur.External)
	}
	// The router reboots and forgets the entry.
	f.mu.Lock()
	clear(f.maps)
	f.mu.Unlock()
	if lost, _, err := c.Check(ctx); err != nil || !lost {
		t.Fatalf("lost entry not noticed: lost %v err %v", lost, err)
	}
	if _, err := c.Map(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.maps) != 0 || f.deletes != 1 {
		t.Fatalf("after close: %v, %d deletes", f.maps, f.deletes)
	}
}

func TestUPnPConflictTriesAnotherPort(t *testing.T) {
	f := newFakeIGD(t)
	f.conflictFirst = true
	c := newClient(t, upnpOptions(f))
	m, err := c.Map(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.External.Port() == testPort || m.External.Port() < 1024 {
		t.Fatalf("external port %d", m.External.Port())
	}
}

func TestUPnPRefusesPermanentLeases(t *testing.T) {
	f := newFakeIGD(t)
	f.permanentOnly = true
	c := newClient(t, upnpOptions(f))
	if _, err := c.Map(context.Background()); !errors.Is(err, ErrPermanentOnly) {
		t.Fatalf("got %v, want ErrPermanentOnly", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.maps) != 0 {
		t.Fatalf("mapping made: %v", f.maps)
	}
}

func TestUPnPFollowsOnlyGatewayURLs(t *testing.T) {
	f := newFakeIGD(t)
	// A LOCATION on another host (here a TEST-NET address) is never
	// fetched; the same for a host name.
	for _, loc := range []string{"http://198.51.100.1:5000/rootDesc.xml", "http://localhost" + f.srv.URL[len("http://127.0.0.1"):] + "/rootDesc.xml", "https://127.0.0.1/x.xml"} {
		f.location = loc
		c := newClient(t, upnpOptions(f))
		if _, err := c.Map(context.Background()); err == nil {
			t.Fatalf("LOCATION %s followed", loc)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fetches != 0 {
		t.Fatalf("description fetched %d times", f.fetches)
	}
}

func TestOnGatewayControlURL(t *testing.T) {
	c := newClient(t, testOptions(1, 1))
	for _, ok := range []string{"http://127.0.0.1:5000/ctl", "http://127.0.0.1/ctl"} {
		if _, err := c.onGateway(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://127.0.0.2/ctl", "http://user@127.0.0.1/", "ftp://127.0.0.1/", "http://127.0.0.1:0/", "http://127.0.0.1:99999/", "//127.0.0.1/"} {
		if _, err := c.onGateway(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParseSOAP(t *testing.T) {
	out, err := parseSOAPResponse([]byte(soapReply("GetExternalIPAddress", "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>")))
	if err != nil || out["NewExternalIPAddress"] != "203.0.113.7" {
		t.Fatalf("%v %v", out, err)
	}
	_, err = parseSOAPResponse([]byte(soapFaultReply(718, "ConflictInMappingEntry")))
	if faultCode(err) != 718 {
		t.Fatalf("fault: %v", err)
	}
	if _, err := parseSOAPResponse([]byte("<a>")); err == nil {
		t.Fatal("broken XML accepted")
	}
}

func TestSOAPBodyEscapes(t *testing.T) {
	b := string(soapBody("urn:x", "AddPortMapping", []soapArg{{"NewPortMappingDescription", `<&">`}}))
	if strings.Contains(b, `<&">`) {
		t.Fatalf("not escaped: %s", b)
	}
}

func TestParseDescriptionPrefersIPConnection(t *testing.T) {
	desc := strings.Replace(testDescription, "</serviceList>\n   </device>", `<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ctl/PPP</controlURL></service></serviceList>
   </device>`, 1)
	_, svc, err := parseDescription([]byte(desc))
	if err != nil || svc.ControlURL != "/ctl/IPConn" {
		t.Fatalf("%+v %v", svc, err)
	}
	if _, _, err := parseDescription([]byte(`<root><device><deviceType>x</deviceType></device></root>`)); err == nil {
		t.Fatal("description without a WAN service accepted")
	}
}

func TestProtocolString(t *testing.T) {
	for p, want := range map[Protocol]string{ProtoPCP: "PCP", ProtoNATPMP: "NAT-PMP", ProtoUPnP: "UPnP-IGD", ProtoNone: "yok"} {
		if p.String() != want {
			t.Errorf("%d: %s", p, p.String())
		}
	}
	if !IsPublic(publicIP) || IsPublic(netip.MustParseAddr("10.1.1.1")) || IsPublic(netip.MustParseAddr("100.100.1.1")) || IsPublic(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IsPublic")
	}
	_ = fmt.Sprint(ErrNotPublic)
}
