package panel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCallerAllowed(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := httptest.NewRequest(http.MethodGet, "/api/app/tray", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	if !callerAllowed(nil, req, logger) {
		t.Fatal("no check must allow")
	}
	deny := func(string, string) error { return errors.New("not admin") }
	if callerAllowed(deny, req, logger) {
		t.Fatal("a check without a local address must refuse")
	}
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47821}
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, net.Addr(local)))
	var gotRemote, gotLocal string
	allow := func(remote, l string) error { gotRemote, gotLocal = remote, l; return nil }
	if !callerAllowed(allow, req, logger) || gotRemote != "127.0.0.1:50000" || gotLocal != "127.0.0.1:47821" {
		t.Fatalf("allow: remote %q local %q", gotRemote, gotLocal)
	}
	if callerAllowed(deny, req, logger) {
		t.Fatal("a refusing check must refuse")
	}
}

func TestAdvancedSettingsChecks(t *testing.T) {
	if (AdvancedSettings{}).hasChange() {
		t.Fatal("empty request has a change")
	}
	on := true
	if !(AdvancedSettings{LazyPeers: &on}).hasChange() {
		t.Fatal("lazy peers change missed")
	}
	neg, huge := int64(-1), int64(maxAdvancedSeconds+1)
	if (AdvancedSettings{KeepaliveSec: &neg}).transportInRange() || (AdvancedSettings{LazyIdleSec: &huge}).transportInRange() {
		t.Fatal("out of range seconds accepted")
	}
	long := string(make([]byte, maxAdvancedAddr+1))
	if (AdvancedSettings{TCPFallback: &long}).transportInRange() {
		t.Fatal("over-long address accepted")
	}
}
