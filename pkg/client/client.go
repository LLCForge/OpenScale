// Package client is the Go client of the OpenScale local API (ADR-0108,
// docs/api/yerel-api.md): the loopback HTTP API that the desktop service
// and a foreground "openscale up" offer to programs on the same computer.
//
// The caller needs the same rights as the openscale command line: on
// Windows an elevated administrator or SYSTEM (the service's app token is
// readable only by them), on Linux root, the user who started the tunnel
// or a member of the "openscale" group (ADR-0050). The tunnel checks the
// calling process too, so knowing the token alone is not enough.
//
// The client connects only to loopback, never through a proxy, never
// follows redirects and bounds every answer.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/winapp"
)

const (
	// Prefix is the local API's path prefix.
	Prefix = "/api/local"
	// ServicePort is the desktop service's loopback port.
	ServicePort = 47821
	// ServiceTokenFile is the app token in the service's data directory.
	ServiceTokenFile = "app.token"
	// StateFile tells where "openscale up" serves the API, in its state
	// directory.
	StateFile = "local-api.json"

	minToken      = 32
	maxToken      = 256
	maxStateFile  = 4 << 10
	maxReply      = 1 << 20
	callTimeout   = 20 * time.Second
	probeTimeout  = 2 * time.Second
	maxPollWait   = 30 * time.Second
	maxQueryChars = 253
)

// serviceDataDir is the Windows service's data directory ("" elsewhere).
var serviceDataDir = winapp.DataDir

// ErrNotRunning means no tunnel's local API was found on this computer.
var ErrNotRunning = errors.New("openscale: no running tunnel found (start the service or 'openscale up', and run with the same rights as the openscale command)")

// Error is an error answer of the API.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("openscale local API: %d: %s", e.Status, e.Message)
}

// Client calls one tunnel's local API. It is safe for concurrent use.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for base ("http://127.0.0.1:<port>") and token.
// Any address other than loopback is refused.
func New(base, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("openscale: base must be http://127.0.0.1:<port>")
	}
	ap, err := netip.ParseAddrPort(u.Host)
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
		return nil, errors.New("openscale: the local API is reachable only on a loopback address")
	}
	if len(token) < minToken || len(token) > maxToken || strings.ContainsAny(token, " \r\n\t") {
		return nil, errors.New("openscale: token is malformed")
	}
	return &Client{base: "http://" + ap.String(), token: token, http: &http.Client{
		Timeout: callTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

type stateInfo struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

// FromStateDir reads the API address and token "openscale up" wrote into
// its state directory.
func FromStateDir(dir string) (*Client, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, StateFile), maxStateFile)
	if err != nil {
		return nil, err
	}
	var info stateInfo
	if err := json.Unmarshal(data, &info); err != nil || info.Port < 1 || info.Port > 65535 {
		return nil, errors.New("openscale: local API file is corrupt")
	}
	return New("http://127.0.0.1:"+strconv.Itoa(info.Port), info.Token)
}

// FromServiceDir reads the desktop service's app token from its data
// directory ("" for the default) and uses the service's port.
func FromServiceDir(dataDir string) (*Client, error) {
	if dataDir == "" {
		dataDir = serviceDataDir()
	}
	if dataDir == "" {
		return nil, ErrNotRunning
	}
	data, err := securefile.ReadPrivate(filepath.Join(dataDir, ServiceTokenFile), maxToken)
	if err != nil {
		return nil, err
	}
	return New("http://127.0.0.1:"+strconv.Itoa(ServicePort), strings.TrimSpace(string(data)))
}

// DefaultStateDir is the per-user state directory "openscale up" uses
// without --state-dir.
func DefaultStateDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return "", errors.New("openscale: user config directory unknown")
	}
	return filepath.Join(base, "OpenScale"), nil
}

// Discover finds the running tunnel: the desktop service first (Windows),
// then "openscale up" with stateDir ("" for the default). It returns
// fs.ErrPermission wrapped when a token exists but cannot be read.
func Discover(ctx context.Context, stateDir string) (*Client, error) {
	var permErr error
	if runtime.GOOS == "windows" {
		c, err := FromServiceDir("")
		switch {
		case err == nil:
			if c.reachable(ctx) {
				return c, nil
			}
		case errors.Is(err, fs.ErrPermission):
			permErr = fmt.Errorf("openscale: run as administrator to read the service token: %w", err)
		}
	}
	if stateDir == "" {
		d, err := DefaultStateDir()
		if err == nil {
			stateDir = d
		}
	}
	if stateDir != "" {
		c, err := FromStateDir(stateDir)
		switch {
		case err == nil:
			if c.reachable(ctx) {
				return c, nil
			}
		case errors.Is(err, fs.ErrPermission) && permErr == nil:
			permErr = fmt.Errorf("openscale: the tunnel's token is not readable by this user: %w", err)
		}
	}
	if permErr != nil {
		return nil, permErr
	}
	return nil, ErrNotRunning
}

func (c *Client) reachable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	_, err := c.Health(ctx)
	return err == nil
}

// call sends one request; path is below Prefix.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+Prefix+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("openscale: local API unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if err != nil {
		return err
	}
	if len(data) > maxReply {
		return errors.New("openscale: local API answer too large")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return &Error{Status: resp.StatusCode, Message: e.Error}
		}
		return &Error{Status: resp.StatusCode, Message: resp.Status}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Status returns this device, its peers and the tunnel's state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	return out, c.call(ctx, http.MethodGet, "/status", nil, &out)
}

// Health returns the liveness and readiness of the tunnel.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var out Health
	return out, c.call(ctx, http.MethodGet, "/health", nil, &out)
}

// Paths returns how each peer is reached (direct or relay).
func (c *Client) Paths(ctx context.Context) (Paths, error) {
	var out Paths
	return out, c.call(ctx, http.MethodGet, "/paths", nil, &out)
}

// Events returns the recent event list.
func (c *Client) Events(ctx context.Context) (Events, error) {
	var out Events
	return out, c.call(ctx, http.MethodGet, "/events", nil, &out)
}

// EventsSince waits up to wait (at most 30 s) for events after since and
// returns them with the sequence number to ask from next.
func (c *Client) EventsSince(ctx context.Context, since uint64, wait time.Duration) (EventBatch, error) {
	if wait < 0 {
		wait = 0
	}
	wait = min(wait, maxPollWait)
	var out EventBatch
	path := "/events/poll?since=" + strconv.FormatUint(since, 10) + "&wait=" + strconv.Itoa(int(wait/time.Second))
	return out, c.call(ctx, http.MethodGet, path, nil, &out)
}

// DNS returns the MagicDNS and network DNS state.
func (c *Client) DNS(ctx context.Context) (DNS, error) {
	var out DNS
	return out, c.call(ctx, http.MethodGet, "/dns", nil, &out)
}

// Prefs returns the persistent preferences.
func (c *Client) Prefs(ctx context.Context) (Prefs, error) {
	var out Prefs
	return out, c.call(ctx, http.MethodGet, "/prefs", nil, &out)
}

// WhoIs returns the device behind a tunnel address. addr may be an IP
// address, "ip:port" (a connection's remote address) or a device name.
// The answer has no Device when the address belongs to no device.
func (c *Client) WhoIs(ctx context.Context, addr string) (WhoIsResult, error) {
	q := strings.TrimSpace(addr)
	if ap, err := netip.ParseAddrPort(q); err == nil {
		q = ap.Addr().Unmap().String()
	}
	if q == "" || len(q) > maxQueryChars {
		return WhoIsResult{}, errors.New("openscale: address or name required")
	}
	var out WhoIsResult
	return out, c.call(ctx, http.MethodGet, "/whois?q="+url.QueryEscape(q), nil, &out)
}
