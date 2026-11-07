// Package desktop is the desktop app: on Windows the double-click
// experience (ADR-0014), the elevated tray app that installs and talks to
// the OpenScale service, and the service entry point itself; the macOS
// menu bar app (ADR-0227) and the Linux tray (ADR-0234) with their app
// services.
package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/service"
)

const (
	logDirName     = "logs"
	logFileName    = "service.log"
	maxLogSize     = 10 << 20
	requestTimeout = 5 * time.Second
	maxReplySize   = 64 << 10
)

// trayIconPNG is the tray icon; empty uses the built-in generated icon.
var trayIconPNG []byte

// panelBase is the loopback address of the service's panel.
var panelBase = "http://127.0.0.1:" + strconv.Itoa(service.DefaultPanelPort)

// trayClient talks to the service: on Windows to the panel with the app
// token, on macOS and Linux to the service's tray socket, which checks the caller
// through the kernel and adds the token itself (ADR-0227, ADR-0234).
type trayClient struct {
	dataDir string
	http    *http.Client
	// base is where API requests go; "" is the panel (panelBase).
	base string
	// gateway: the transport is the tray socket and carries no token.
	gateway bool
}

func newTrayClient(dataDir string) *trayClient {
	return &trayClient{dataDir: dataDir, http: &http.Client{
		Timeout: requestTimeout,
		// The panel never redirects API calls; refuse to follow anywhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// apiBase is the address API requests go to.
func (c *trayClient) apiBase() string {
	if c.base != "" {
		return c.base
	}
	return panelBase
}

// authorize adds the app token unless the transport is the tray socket.
func (c *trayClient) authorize(req *http.Request) error {
	if c.gateway {
		return nil
	}
	token, err := service.ReadToken(c.dataDir)
	if err != nil {
		return fmt.Errorf("servis henüz hazır değil: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (c *trayClient) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase()+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.authorize(req); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxReplySize))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(reply, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("servis yanıtı: %s", resp.Status)
	}
	return json.Unmarshal(reply, out)
}

func (c *trayClient) status(ctx context.Context) (panel.AppStatus, error) {
	var st panel.AppStatus
	err := c.do(ctx, http.MethodGet, "/api/app/tray", nil, &st)
	return st, err
}

// setConnected turns the tunnel on or off.
func (c *trayClient) setConnected(ctx context.Context, on bool) (panel.AppStatus, error) {
	var st panel.AppStatus
	err := c.do(ctx, http.MethodPost, "/api/app/tray/connect", map[string]bool{"connected": on}, &st)
	return st, err
}

// setExit chooses the exit node ("" for none).
func (c *trayClient) setExit(ctx context.Context, name string) error {
	var st panel.AppStatus
	return c.do(ctx, http.MethodPost, "/api/app/tray/exit", map[string]string{"name": name}, &st)
}

// setExitOptions sets the kill switch and local network access.
func (c *trayClient) setExitOptions(ctx context.Context, killSwitch, allowLAN bool) error {
	var st panel.AppStatus
	return c.do(ctx, http.MethodPost, "/api/app/tray/exit/options", map[string]bool{"killSwitch": killSwitch, "exitAllowLan": allowLAN}, &st)
}

// disconnectFor turns the tunnel off for a while (panel.Disconnect5Min,
// Disconnect1Hour or DisconnectMorning).
func (c *trayClient) disconnectFor(ctx context.Context, choice string) error {
	var st panel.AppStatus
	return c.do(ctx, http.MethodPost, "/api/app/tray/disconnect", map[string]string{"for": choice}, &st)
}

// releaseOnStop tells the service that the stop that follows is the
// owner's full exit, so it removes the kill switch.
func (c *trayClient) releaseOnStop(ctx context.Context) error {
	var out map[string]bool
	return c.do(ctx, http.MethodPost, "/api/app/tray/release-on-stop", struct{}{}, &out)
}

// panelURL returns a one-time sign-in link to the panel.
func (c *trayClient) panelURL(ctx context.Context) (string, error) {
	var out struct {
		Ticket string `json:"ticket"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/app/ticket", nil, &out); err != nil {
		return "", err
	}
	if out.Ticket == "" {
		return "", errors.New("servis giriş bileti vermedi")
	}
	return panelBase + "/auth/ticket?t=" + url.QueryEscape(out.Ticket), nil
}

// waitReady polls until the service answers or the deadline passes.
func (c *trayClient) waitReady(ctx context.Context, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		_, err := c.status(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("servis başlamadı: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Version is shown in the About box; main sets it from the build.
var Version = "dev"

// maxTrayNameRunes keeps the network name short enough for the tray
// tooltip, which Windows cuts at 127 characters.
const maxTrayNameRunes = 32

// trayTitle is "OpenScale", followed by the network's display name when
// the owner set one (F-160). The name comes from the signed document,
// which refuses control and formatting characters.
func trayTitle(st panel.AppStatus) string {
	name := []rune(st.NetworkName)
	if len(name) == 0 {
		return "OpenScale"
	}
	if len(name) > maxTrayNameRunes {
		name = append(name[:maxTrayNameRunes-1], '…')
	}
	return "OpenScale - " + string(name)
}

// connectionLabel is the state shown next to "OpenScale" in the tray.
func connectionLabel(st panel.AppStatus) string {
	switch {
	case st.Mode == panel.ModeSetup:
		return "Kurulum bekliyor"
	case st.Mode == panel.ModeJoining && st.Joining != nil && st.Joining.ShortCode != "":
		return "Onay bekleniyor (" + st.Joining.ShortCode + ")"
	case st.Mode == panel.ModeJoining:
		return "Ağa katılıyor"
	case st.Device == nil:
		return "Bağlı değil"
	case !st.Device.Connected && st.Device.DisconnectedUntil != nil:
		return "Bağlantı kapalı (" + untilLabel(*st.Device.DisconnectedUntil, time.Now()) + " açılır)"
	case !st.Device.Connected:
		return "Bağlantı kapalı"
	case st.Device.Error != "":
		return "Tünel açılamadı"
	case st.Device.Running && st.Device.LastSyncError == "" && st.Device.LastSync != nil && st.Device.CoordinatorOverTCP:
		// UDP is blocked; the control traffic uses TCP (ADR-0032).
		return "Bağlı (koordinatöre TCP ile)"
	case st.Device.Running && st.Device.LastSyncError == "" && st.Device.LastSync != nil:
		return "Bağlı"
	case st.Device.Running && st.Device.LastSync == nil:
		return "Bağlanıyor"
	case st.Device.Running:
		return "Koordinatöre ulaşılamıyor"
	default:
		return "Bağlanıyor"
	}
}

// untilLabel names the end of a timed disconnect: the time today, or the
// day and time when it is on another day.
func untilLabel(t, now time.Time) string {
	t, now = t.Local(), now.Local()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Format("15:04")
	}
	if tomorrow := now.AddDate(0, 0, 1); t.Year() == tomorrow.Year() && t.YearDay() == tomorrow.YearDay() {
		return "yarın " + t.Format("15:04")
	}
	return t.Format("02.01 15:04")
}

// serviceLogger writes JSON logs under the data directory and keeps one
// previous file once the current one passes 10 MB.
func serviceLogger(dataDir string) (*slog.Logger, func(), error) {
	dir := filepath.Join(dataDir, logDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, logFileName)
	// Rotated by size while running, kept for logMaxAge (#43).
	f, err := openRotatingLog(path, maxLogSize, logKeep, logMaxAge, time.Now)
	if err != nil {
		return nil, nil, err
	}
	// The level can be changed while the service runs (openscale log level).
	// Info and above never carry IP addresses, no level carries keys (#42).
	// On a nearly full disk the log pauses so the network document can
	// still be written (#205, ADR-0095).
	guarded := diskguard.NewWriter(f, dir, 0)
	// Debug records (with addresses) go only to the encrypted debug log
	// (ADR-0060, ADR-0110).
	h, sealed := service.NewDebugCryptHandler(slog.NewJSONHandler(guarded, &slog.HandlerOptions{Level: service.LogLevel}), dir,
		func() ([]byte, error) { return service.DeviceSigningSeed(dataDir) }, service.LogLevel)
	return privacy.NewMaskedLogger(h), func() { _ = sealed.Close(); _ = f.Close() }, nil
}
