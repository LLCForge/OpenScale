package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/audit"
)

// fakeObs is an Observability that records what it was asked.
type fakeObs struct {
	metricsOn bool
	captured  CaptureRequest
}

func (f *fakeObs) Denied() (DeniedReply, error) {
	return DeniedReply{Schema: DiagSchema, Entries: []DeniedEntry{{Direction: "in", Peer: "laptop", Proto: "tcp", Port: 22, Reason: DenyNoRule, Count: 3}}, Totals: map[string]uint64{"rules": 3}}, nil
}
func (f *fakeObs) ClearDenied() error { return nil }
func (f *fakeObs) WriteMetrics(w io.Writer) error {
	if !f.metricsOn {
		return ErrMetricsOff
	}
	_, err := io.WriteString(w, "openscale_tunnel_up 1\n")
	return err
}
func (f *fakeObs) EventsSince(_ context.Context, since uint64, _ time.Duration) EventStreamReply {
	if since >= 2 {
		return EventStreamReply{Schema: DiagSchema, Events: []StreamEvent{}, Next: since}
	}
	return EventStreamReply{Schema: DiagSchema, Next: 2, Notifications: true, Events: []StreamEvent{
		{Seq: 1, Kind: "device_added", Message: "Ağa yeni cihaz eklendi: telefon.", Notify: true},
		{Seq: 2, Kind: "peer_online", Message: "telefon çevrimiçi oldu."},
	}}
}
func (f *fakeObs) AuditTail(int) (AuditReply, error) {
	return AuditReply{Schema: DiagSchema, Records: []audit.Record{{Seq: 1, Kind: "service_started"}}, Verify: audit.Report{OK: true}}, nil
}
func (f *fakeObs) AuditVerify() (audit.Report, error) { return audit.Report{OK: true, Records: 1}, nil }
func (f *fakeObs) Bundle(context.Context) (BundleReply, error) {
	return BundleReply{Schema: DiagSchema, Files: []BundleFile{{Name: "README.txt", Content: "x"}}}, nil
}
func (f *fakeObs) Capture(_ context.Context, req CaptureRequest, w io.Writer) (CaptureSummary, error) {
	f.captured = req
	_, err := w.Write([]byte{0xd4, 0xc3, 0xb2, 0xa1})
	return CaptureSummary{Packets: 7, Dropped: 1}, err
}
func (f *fakeObs) Profile(context.Context, ProfileRequest, io.Writer) error { return ErrProfilingOff }
func (f *fakeObs) ObservePrefs() ObservePrefs {
	return ObservePrefs{Schema: DiagSchema, Metrics: f.metricsOn, Notifications: true}
}
func (f *fakeObs) SetObservePrefs(c ObservePrefsChange) (ObservePrefs, error) {
	if c.Metrics != nil {
		f.metricsOn = *c.Metrics
	}
	return f.ObservePrefs(), nil
}

type obsDiagApp struct {
	*diagApp
	obs *fakeObs
}

func (a obsDiagApp) Observability() Observability { return a.obs }

func TestObserveLocalAPI(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 40)
	obs := &fakeObs{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeLocalAPI(ctx, ln, LocalAPIConfig{Diag: obsDiagApp{diagApp: &diagApp{level: "info"}, obs: obs}, Token: token})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()
	base := "http://" + ln.Addr().String() + LocalAPIPrefix
	call := func(method, path, body string) *http.Response {
		t.Helper()
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, base+path, r)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	status := func(resp *http.Response) int {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	var denied DeniedReply
	resp := call(http.MethodGet, "/denied", "")
	if err := json.NewDecoder(resp.Body).Decode(&denied); err != nil || len(denied.Entries) != 1 {
		t.Fatalf("denied: %+v %v", denied, err)
	}
	resp.Body.Close()

	if c := status(call(http.MethodGet, "/metrics", "")); c != http.StatusNotFound {
		t.Fatalf("metrics while off: %d", c)
	}
	if c := status(call(http.MethodPost, "/observe", `{"metrics":true}`)); c != http.StatusOK {
		t.Fatalf("metrics on: %d", c)
	}
	resp = call(http.MethodGet, "/metrics", "")
	text, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") || string(text) != "openscale_tunnel_up 1\n" {
		t.Fatalf("metrics: %d %q", resp.StatusCode, text)
	}

	var ev EventStreamReply
	resp = call(http.MethodGet, "/events/poll?since=0&wait=1", "")
	if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil || len(ev.Events) != 2 || ev.Next != 2 {
		t.Fatalf("poll: %+v %v", ev, err)
	}
	resp.Body.Close()
	if c := status(call(http.MethodGet, "/events/poll?wait=999", "")); c != http.StatusBadRequest {
		t.Fatalf("long wait accepted: %d", c)
	}

	// The event stream sends the events as SSE.
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	req, _ := http.NewRequestWithContext(sctx, http.MethodGet, base+"/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("stream content type %q", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	var ids []string
	for sc.Scan() && len(ids) < 2 {
		if id, ok := strings.CutPrefix(sc.Text(), "id: "); ok {
			ids = append(ids, id)
		}
	}
	scancel()
	resp.Body.Close()
	if strings.Join(ids, ",") != "1,2" {
		t.Fatalf("stream ids %v", ids)
	}

	// Capture: validation, then a pcap body with trailers.
	if c := status(call(http.MethodPost, "/capture", `{"seconds":0,"max_bytes":4096}`)); c != http.StatusBadRequest {
		t.Fatalf("zero seconds accepted: %d", c)
	}
	if c := status(call(http.MethodPost, "/capture", `{"seconds":5,"max_bytes":4096,"peer":"a b"}`)); c != http.StatusBadRequest {
		t.Fatalf("bad peer accepted: %d", c)
	}
	resp = call(http.MethodPost, "/capture", `{"seconds":5,"max_bytes":4096,"peer":"laptop","proto":"tcp","port":22}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(body) != 4 || resp.Trailer.Get("X-Capture-Packets") != "7" || resp.Trailer.Get("X-Capture-Dropped") != "1" {
		t.Fatalf("capture: %d %v %v", resp.StatusCode, body, resp.Trailer)
	}
	if obs.captured.Peer != "laptop" || obs.captured.Port != 22 {
		t.Fatalf("capture request %+v", obs.captured)
	}

	if c := status(call(http.MethodPost, "/pprof", `{"kind":"heap"}`)); c != http.StatusForbidden {
		t.Fatalf("profiling while off: %d", c)
	}
	if c := status(call(http.MethodPost, "/pprof", `{"kind":"cpu","seconds":0}`)); c != http.StatusBadRequest {
		t.Fatalf("cpu without seconds: %d", c)
	}
	if c := status(call(http.MethodGet, "/audit?n=0", "")); c != http.StatusBadRequest {
		t.Fatalf("audit n=0: %d", c)
	}
	if c := status(call(http.MethodGet, "/audit/verify", "")); c != http.StatusOK {
		t.Fatalf("audit verify: %d", c)
	}
	if c := status(call(http.MethodGet, "/bundle", "")); c != http.StatusOK {
		t.Fatalf("bundle: %d", c)
	}
}

func TestObserveWithoutSource(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 40)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeLocalAPI(ctx, ln, LocalAPIConfig{Diag: &diagApp{}, Token: token}) }()
	defer func() { cancel(); <-done }()
	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+LocalAPIPrefix+"/denied", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("without observability: %d", resp.StatusCode)
	}
}
