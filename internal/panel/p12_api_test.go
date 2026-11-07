package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/usagehist"
)

func TestErrorCatalogEndpoints(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	if rec := do(t, h, http.MethodGet, "/api/errors", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("catalog without session = %d", rec.Code)
	}
	cookie, csrf := login(t, srv)
	withCookie := func(r *http.Request) { r.AddCookie(cookie) }
	rec := do(t, h, http.MethodGet, "/api/errors", nil, withCookie)
	var cat ErrorCatalogReply
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil || rec.Code != http.StatusOK || len(cat.Codes) < 40 || cat.Catalog < 1 {
		t.Fatalf("catalog %d: %v", rec.Code, err)
	}
	rec = do(t, h, http.MethodGet, "/api/errors?q=windows+guvenlik", nil, withCookie)
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil || len(cat.Codes) == 0 || cat.Codes[0].Code != "OS-5004" {
		t.Fatalf("search: %s", rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/errors/os3001", nil, withCookie)
	var one ErrorCodeReply
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil || one.Code != "OS-3001" || len(one.Steps) == 0 || one.Doc != "sorun-giderme.md#os-3001" {
		t.Fatalf("one: %s", rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/errors/OS-7999", nil, withCookie); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown code = %d", rec.Code)
	}

	// A failed change carries its stable code next to the message.
	bad := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+testHost)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	rec = do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": "yanlış parola 123456"}, bad)
	var e struct{ Error, Code string }
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || rec.Code != http.StatusUnauthorized || e.Code != "OS-1001" || e.Error == "" {
		t.Fatalf("renew with wrong passphrase: %d %s", rec.Code, rec.Body)
	}
}

func TestNetworkReportEndpoint(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie, _ := login(t, srv)
	withCookie := func(r *http.Request) { r.AddCookie(cookie) }
	rec := do(t, h, http.MethodGet, "/api/network/report", nil, withCookie)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/markdown") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(rec.Body.String(), "## Cihazlar") {
		t.Fatalf("md: %d %v", rec.Code, rec.Header())
	}
	rec = do(t, h, http.MethodGet, "/api/network/report?format=html", nil, withCookie)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), ".html") || !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatalf("html: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/network/report?format=json", nil, withCookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"devices"`) {
		t.Fatalf("json: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/network/report?format=pdf", nil, withCookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/network/report", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without session = %d", rec.Code)
	}
}

// historyObs adds the histories to the observability fake.
type historyObs struct {
	*fakeObs
	traffic *usagehist.Traffic
	res     *usagehist.Resources
	now     time.Time
}

func (h historyObs) TrafficHistory(device string, hours int) (TrafficHistoryReply, error) {
	rep := TrafficHistoryReply{Schema: DiagSchema, Hours: hours, Device: device, Devices: []TrafficDeviceTotal{}}
	for _, d := range h.traffic.Devices() {
		rx, tx := h.traffic.Total(d, hours, h.now)
		rep.Devices = append(rep.Devices, TrafficDeviceTotal{Name: d, Rx: rx, Tx: tx})
	}
	if device != "" {
		rep.Points = h.traffic.Series(device, hours, h.now)
	}
	return rep, nil
}

func (h historyObs) ResourceUsage() ResourceReply {
	return ResourceReply{Schema: DiagSchema, SampleEverySeconds: 300, Summary: h.res.Summarize(), Samples: h.res.Samples()}
}

type historyDiagApp struct {
	*diagApp
	obs Observability
}

func (a historyDiagApp) Observability() Observability { return a.obs }

func TestHistoryLocalAPI(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 30, 0, 0, time.UTC)
	tr := usagehist.NewTraffic()
	tr.Observe("nas", 0, 0, now)
	tr.Observe("nas", 4096, 1024, now)
	res := usagehist.NewResources(usagehist.Probe{CPU: func() (time.Duration, bool) { return time.Second, true }})
	res.Sample(now.Add(-10 * time.Minute))
	res.Sample(now)

	for _, withHistory := range []bool{true, false} {
		var obs Observability = &fakeObs{}
		if withHistory {
			obs = historyObs{fakeObs: &fakeObs{}, traffic: tr, res: res, now: now}
		}
		ln, err := Listen(0)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.Repeat("t", 40)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- ServeLocalAPI(ctx, ln, LocalAPIConfig{Diag: historyDiagApp{diagApp: &diagApp{level: "info"}, obs: obs}, Token: token})
		}()
		get := func(path string) (int, []byte) {
			req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+LocalAPIPrefix+path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, body
		}
		if !withHistory {
			if c, _ := get("/traffic-history"); c != http.StatusNotFound {
				t.Fatalf("history without support = %d", c)
			}
			cancel()
			<-done
			continue
		}
		c, body := get("/traffic-history?device=nas&hours=2")
		var rep TrafficHistoryReply
		if err := json.Unmarshal(body, &rep); err != nil || c != http.StatusOK || len(rep.Points) != 2 || rep.Points[1].Rx != 4096 || len(rep.Devices) != 1 {
			t.Fatalf("history %d: %s", c, body)
		}
		for _, q := range []string{"?hours=0", "?hours=721", "?device=a/b", "?device=" + strings.Repeat("a", 200)} {
			if c, _ := get("/traffic-history" + q); c != http.StatusBadRequest {
				t.Errorf("%s = %d", q, c)
			}
		}
		c, body = get("/resources")
		var rr ResourceReply
		if err := json.Unmarshal(body, &rr); err != nil || c != http.StatusOK || rr.Summary.Samples != 1 || rr.SampleEverySeconds != 300 {
			t.Fatalf("resources %d: %s", c, body)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
