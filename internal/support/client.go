package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// Client asks another device's support service. The answer comes from a
// device that may be compromised, so it is size-limited, decoded strictly
// and cleaned again before anyone sees it.
type Client struct {
	http *http.Client
}

// DialFunc opens a connection inside the tunnel.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// NewClient returns a client that dials with dial (nil: the system dialer).
func NewClient(dial DialFunc) *Client {
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	tr := &http.Transport{
		DialContext:            dial,
		Proxy:                  nil,
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  DefaultConsentTimeout + collectTimeout + 10*time.Second,
		MaxResponseHeaderBytes: 8 << 10,
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: DefaultConsentTimeout + collectTimeout + 20*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// RemoteError is an error the remote device answered with.
type RemoteError struct {
	Status  int
	Message string
}

func (e *RemoteError) Error() string { return e.Message }

func endpoint(addr netip.AddrPort, path string, q url.Values) string {
	u := url.URL{Scheme: "http", Host: addr.String(), Path: path}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (c *Client) do(ctx context.Context, method, target string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cihaza ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > MaxResponse {
		return errors.New("cihazın yanıtı çok büyük")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		msg := clean(e.Error, 256)
		if msg == "" {
			msg = fmt.Sprintf("cihaz %d ile yanıt verdi", resp.StatusCode)
		}
		return &RemoteError{Status: resp.StatusCode, Message: msg}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// Snapshot fetches one kind from the device at addr.
func (c *Client) Snapshot(ctx context.Context, addr netip.AddrPort, kind string) (Snapshot, error) {
	if !ValidKind(kind) {
		return Snapshot{}, fmt.Errorf("bilinmeyen tür %q", kind)
	}
	var s Snapshot
	if err := c.do(ctx, http.MethodGet, endpoint(addr, "/v1/snapshot", url.Values{"kind": {kind}}), nil, &s); err != nil {
		return Snapshot{}, err
	}
	if s.Kind != kind {
		return Snapshot{}, errors.New("cihaz başka bir tür döndürdü")
	}
	// Clean again: the remote side may not be honest about its limits.
	s.Clean()
	return s, nil
}

// Kill asks the device to end process pid with the given name.
func (c *Client) Kill(ctx context.Context, addr netip.AddrPort, pid int, name string) error {
	if pid <= 0 || name == "" || len(name) > MaxNameLen {
		return errors.New("süreç geçersiz")
	}
	var out map[string]bool
	return c.do(ctx, http.MethodPost, endpoint(addr, "/v1/kill", nil), KillRequest{PID: pid, Name: name}, &out)
}

// End closes this device's session on addr.
func (c *Client) End(ctx context.Context, addr netip.AddrPort) error {
	var out map[string]bool
	return c.do(ctx, http.MethodPost, endpoint(addr, "/v1/end", nil), struct{}{}, &out)
}
