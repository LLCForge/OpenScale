package osnet

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type fakeBSD struct {
	calls []string
	// replies maps a command line prefix to its output and error.
	replies map[string]struct {
		out string
		err error
	}
}

func (f *fakeBSD) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	for prefix, r := range f.replies {
		if strings.HasPrefix(line, prefix) {
			return []byte(r.out), r.err
		}
	}
	return nil, nil
}

func bsdTestConfig() Config {
	return Config{
		Interface: "OpenScale",
		IPv4:      netip.MustParsePrefix("100.80.0.7/16"),
		IPv6:      netip.MustParsePrefix("fd7a:115c:a1e0::7/48"),
		MTU:       1280,
	}
}

func TestConfigureFreeBSD(t *testing.T) {
	f := &fakeBSD{}
	if err := configureBSD(context.Background(), f.run, flavorFreeBSD, bsdTestConfig()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/sbin/ifconfig OpenScale mtu 1280",
		"/sbin/ifconfig OpenScale inet 100.80.0.7/16 alias",
		"/sbin/ifconfig OpenScale inet6 fd7a:115c:a1e0::7 prefixlen 48 alias",
		"/sbin/ifconfig OpenScale up",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestConfigureOpenBSDAddsOverlayRoutes(t *testing.T) {
	f := &fakeBSD{replies: map[string]struct {
		out string
		err error
	}{
		// The IPv6 prefix route may already exist; that is fine.
		"/sbin/route -q -n add -inet6": {"add net fd7a:115c:a1e0::/48: gateway fd7a:115c:a1e0::7: File exists", errors.New("exit status 1")},
	}}
	c := bsdTestConfig()
	c.Interface = "tun0"
	if err := configureBSD(context.Background(), f.run, flavorOpenBSD, c); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/sbin/ifconfig tun0 mtu 1280",
		"/sbin/ifconfig tun0 inet 100.80.0.7/16 alias",
		"/sbin/ifconfig tun0 inet6 fd7a:115c:a1e0::7 prefixlen 48 alias",
		"/sbin/ifconfig tun0 up",
		"/sbin/route -q -n add -inet 100.80.0.0/16 -iface 100.80.0.7",
		"/sbin/route -q -n add -inet6 fd7a:115c:a1e0::/48 -iface fd7a:115c:a1e0::7",
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestConfigureBSDStopsOnError(t *testing.T) {
	f := &fakeBSD{replies: map[string]struct {
		out string
		err error
	}{
		"/sbin/ifconfig tun0 inet ":   {"ifconfig: SIOCAIFADDR: Permission denied", errors.New("exit status 1")},
		"/sbin/route -q -n add -inet": {"route: writing to routing socket: Network is unreachable", errors.New("exit status 1")},
	}}
	c := bsdTestConfig()
	c.Interface = "tun0"
	if err := configureBSD(context.Background(), f.run, flavorOpenBSD, c); err == nil {
		t.Fatal("ifconfig failure ignored")
	}
	if len(f.calls) != 2 {
		t.Fatalf("continued after failure: %v", f.calls)
	}

	// A route failure other than "File exists" is an error.
	f = &fakeBSD{replies: map[string]struct {
		out string
		err error
	}{
		"/sbin/route -q -n add -inet ": {"route: writing to routing socket: Network is unreachable", errors.New("exit status 1")},
	}}
	if err := configureBSD(context.Background(), f.run, flavorOpenBSD, c); err == nil {
		t.Fatal("route failure ignored")
	}
}

func TestDefaultGatewaysBSD(t *testing.T) {
	freebsd := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
        fib: 0
  interface: em0
      flags: <UP,GATEWAY,DONE,STATIC>
 recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
       0         0         0         0      1500         1         0
`
	f := &fakeBSD{replies: map[string]struct {
		out string
		err error
	}{"/sbin/route -n get -inet default": {freebsd, nil}}}
	gws, err := defaultGatewaysBSD(context.Background(), f.run)
	if err != nil || len(gws) != 1 || gws[0] != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("gws = %v, %v", gws, err)
	}

	f.replies["/sbin/route -n get -inet default"] = struct {
		out string
		err error
	}{"route: route has not been found\nroute: not in table", errors.New("exit status 1")}
	gws, err = defaultGatewaysBSD(context.Background(), f.run)
	if err != nil || len(gws) != 0 {
		t.Fatalf("missing default route: %v, %v", gws, err)
	}

	f.replies["/sbin/route -n get -inet default"] = struct {
		out string
		err error
	}{"route: socket: Permission denied", errors.New("exit status 1")}
	if _, err := defaultGatewaysBSD(context.Background(), f.run); err == nil {
		t.Fatal("route failure ignored")
	}
}

func TestParseRouteGetGateway(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"    gateway: 10.0.0.1\n", "10.0.0.1"},
		{"gateway: em0\n", ""},         // interface route
		{"gateway: fe80::1%em0\n", ""}, // not IPv4
		{"gateway: 0.0.0.0\n", ""},
		{"destination: default\n", ""},
	} {
		a, ok := parseRouteGetGateway([]byte(tc.in))
		if (tc.want == "") == ok || (ok && a.String() != tc.want) {
			t.Errorf("%q: got %v %v, want %q", tc.in, a, ok, tc.want)
		}
	}
}

func TestOpenBSDTUNName(t *testing.T) {
	for in, want := range map[string]string{
		"tun":       "tun",
		"tun0":      "tun0",
		"tun12":     "tun12",
		"OpenScale": "tun",
		"tun01":     "tun",
		"tun-1":     "tun",
		"tunx":      "tun",
		"wg0":       "tun",
	} {
		if got := openBSDTUNName(in); got != want {
			t.Errorf("openBSDTUNName(%q) = %q, want %q", in, got, want)
		}
	}
}
