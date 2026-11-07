package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/service"
)

// "openscale rdesk-helper" is started by the Windows service in the user's
// console session (ADR-0110). It is not meant to be run by hand: it reads
// its bootstrap from the pipe the service created and exits when the
// service closes it.

const (
	helperCallTimeout = 10 * time.Second
	helperStatePoll   = 2 * time.Second
	maxBootstrap      = 16 << 10
)

func consentText(req rdesk.ConsentRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s cihazı bu bilgisayara uzak masaüstü ile bağlanmak istiyor.\n\n", req.Peer)
	if req.Mode == rdesk.ModeControl {
		b.WriteString("İstenen: ekranı izleme ve kontrol (klavye, fare, pano).\n")
	} else {
		b.WriteString("İstenen: yalnızca ekranı izleme.\n")
	}
	if req.Code != "" {
		fmt.Fprintf(&b, "Doğrulama kodu: %s\nBu kod bağlanan kişinin ekranındakiyle aynı olmalı; farklıysa reddedin.\n", req.Code)
	}
	if req.Recording {
		b.WriteString("Bu oturum bu bilgisayarda şifreli olarak kaydedilecek.\n")
	}
	b.WriteString("\nİzin veriyor musunuz?")
	return b.String()
}

func indicatorText(ev rdesk.SessionEvent) string {
	var b strings.Builder
	mode := "yalnızca izleme"
	if ev.Mode == rdesk.ModeControl {
		mode = "izleme ve kontrol"
	}
	fmt.Fprintf(&b, "%s cihazı şu anda bu bilgisayarın ekranını görüyor (%s).\n", ev.Peer, mode)
	if ev.Unattended {
		b.WriteString("Oturum kurallardaki gözetimsiz erişim izniyle onaysız açıldı.\n")
	}
	if ev.Recording {
		b.WriteString("Oturum kaydediliyor.\n")
	}
	if ev.Code != "" {
		fmt.Fprintf(&b, "Doğrulama kodu: %s\n", ev.Code)
	}
	b.WriteString("Oturum, bağlanan kişi ayrıldığında veya izin geri alındığında biter.")
	return b.String()
}

// helperClient talks to the service's helper endpoints.
type helperClient struct {
	base   string
	token  string
	http   *http.Client
	events chan panel.RDeskHelperEvent
}

func (c *helperClient) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(ctx, helperCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("servis yanıtı: %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// authorize asks the service; any failure refuses (fail closed).
func (c *helperClient) authorize(remote netip.Addr, mode rdesk.Mode) rdesk.Decision {
	var d panel.RDeskHelperDecision
	if err := c.call(context.Background(), http.MethodPost, "/api/app/rdesk-helper/authorize", map[string]string{"remote": remote.String(), "mode": mode.String()}, &d); err != nil {
		return rdesk.Decision{Reason: "servise sorulamadı"}
	}
	return rdesk.Decision{Allowed: d.Allowed, Unattended: d.Unattended, Peer: d.Peer, Reason: d.Reason, Files: d.Files}
}

func helperEvent(ev rdesk.SessionEvent) panel.RDeskHelperEvent {
	kind := map[rdesk.EventKind]string{rdesk.EventStart: "start", rdesk.EventEnd: "end", rdesk.EventChange: "change"}[ev.Kind]
	return panel.RDeskHelperEvent{Kind: kind, ID: ev.ID, Peer: ev.Peer, Mode: ev.Mode.String(), Unattended: ev.Unattended, Code: ev.Code,
		Recording: ev.Recording, Clipboard: ev.Clipboard, Blank: ev.LocalLock.Blank, InputLock: ev.LocalLock.Input, Reason: ev.Reason}
}

// report queues an event; the indicator must return quickly, so events
// are sent in order by one goroutine.
func (c *helperClient) report(ev panel.RDeskHelperEvent) {
	select {
	case c.events <- ev:
	default:
	}
}

func (c *helperClient) sendEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-c.events:
			_ = c.call(ctx, http.MethodPost, "/api/app/rdesk-helper/event", ev, nil)
		}
	}
}

func (c *helperClient) power(ctx context.Context, req rdesk.PowerRequest) error {
	return c.call(ctx, http.MethodPost, "/api/app/rdesk-helper/power", panel.RDeskHelperPower{Peer: req.Peer, SafeMode: req.SafeMode}, nil)
}

// readBootstrap reads the first line of r.
func readBootstrap(r io.Reader) (service.HelperBootstrap, *bufio.Reader, error) {
	var b service.HelperBootstrap
	br := bufio.NewReaderSize(r, 4096)
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return b, nil, errors.New("başlangıç bilgisi çok uzun")
		}
		return b, nil, errors.New("başlangıç bilgisi okunamadı")
	}
	if len(line) > maxBootstrap {
		return b, nil, errors.New("başlangıç bilgisi çok uzun")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, nil, errors.New("başlangıç bilgisi bozuk")
	}
	return b, br, b.Validate()
}

func cmdRDeskHelper(env *Env, args []string) error {
	if len(args) != 0 {
		return usageError("rdesk-helper argüman almaz; servis tarafından başlatılır")
	}
	boot, rest, err := readBootstrap(env.Stdin)
	if err != nil {
		return fmt.Errorf("rdesk-helper yalnızca OpenScale servisi tarafından başlatılır: %w", err)
	}
	listen, _ := netip.ParseAddrPort(boot.Listen)
	ctx, cancel := context.WithCancel(envContext(env))
	defer cancel()
	c := &helperClient{base: "http://" + boot.API, token: boot.Token, http: newHTTPClient(), events: make(chan panel.RDeskHelperEvent, 64)}
	go c.sendEvents(ctx)
	// The service closes the pipe to stop this helper.
	go func() {
		_, _ = io.Copy(io.Discard, rest)
		cancel()
	}()
	opts := service.RemoteDesktopServerOptions{
		Addr:      listen,
		Authorize: c.authorize,
		Consent:   desktopConsent,
		Indicator: func(ev rdesk.SessionEvent) {
			c.report(helperEvent(ev))
			desktopIndicator(ev)
		},
		LocalLock: boot.LocalLock,
		FileRoots: boot.FileRoots,
		Logger:    slog.New(slog.DiscardHandler),
	}
	if boot.Power {
		opts.Power = c.power
	}
	if boot.RecordingKey != "" {
		key, err := rdesk.ParseRecordingKey([]byte(boot.RecordingKey))
		if err != nil {
			return c.fatal(err)
		}
		dir, err := service.HelperRecordingDir()
		if err != nil {
			return c.fatal(err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return c.fatal(err)
		}
		if boot.RecordingDays > 0 {
			_, _ = rdesk.PruneRecordings(dir, time.Duration(boot.RecordingDays)*24*time.Hour, time.Now())
		}
		opts.RecordingKey, opts.RecordingDir = key, dir
	}
	cfg, err := service.BuildRemoteDesktopConfig(opts)
	if err != nil {
		return c.fatal(err)
	}
	cfg = rdesk.WithSessionFrame(cfg) // #671: "remotely connected" frame in the user session (w1_safety.go)
	srv, err := rdesk.New(cfg)
	if err != nil {
		return c.fatal(err)
	}
	go func() { _ = rdesk.WatchKillShortcut(ctx, srv, nil) }() // #672: Ctrl+Alt+Shift+K ends every session
	go c.watchState(ctx, srv, cancel)
	if err := srv.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		return c.fatal(err)
	}
	return nil
}

// watchState revalidates sessions when the document changed and stops
// when the service asks.
func (c *helperClient) watchState(ctx context.Context, srv *rdesk.Server, stop context.CancelFunc) {
	var gen uint64
	first := true
	t := time.NewTicker(helperStatePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var st panel.RDeskHelperState
		if err := c.call(ctx, http.MethodGet, "/api/app/rdesk-helper/state", nil, &st); err != nil {
			// The service cannot be asked: no new decision is possible, so
			// sessions are checked (and refused) now.
			srv.Revalidate()
			continue
		}
		if st.Stop {
			stop()
			return
		}
		if !first && st.Generation != gen {
			srv.Revalidate()
		}
		gen, first = st.Generation, false
	}
}

// fatal reports a startup failure to the service and returns it.
func (c *helperClient) fatal(err error) error {
	ctx, cancel := context.WithTimeout(context.Background(), helperCallTimeout)
	defer cancel()
	reason := err.Error()
	if len(reason) > 200 {
		reason = reason[:200]
	}
	_ = c.call(ctx, http.MethodPost, "/api/app/rdesk-helper/event", panel.RDeskHelperEvent{Kind: "fatal", Reason: reason}, nil)
	return err
}
