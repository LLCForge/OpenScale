package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/winapp"
)

// The tray's side of the YubiKey administrator mode channel (ADR-0223):
// the app-token local API of the service (loopback, elevated caller, same
// program, #645). Only state and signing requests travel on it; the PIN
// stays in the tray.

const (
	tokenModeTimeout  = 40 * time.Second // above the panel's 25 s long poll
	tokenModeMaxReply = 4 << 20          // a signing request carries a document
)

// tokenModeChannel implements winapp.TokenModeChannel over the local API.
type tokenModeChannel struct {
	base    string
	dataDir string
	http    *http.Client
	// token overrides service.ReadToken (tests).
	token func() (string, error)
}

func newTokenModeChannel(dataDir string) *tokenModeChannel {
	return &tokenModeChannel{base: panelBase, dataDir: dataDir, http: &http.Client{
		Timeout:       tokenModeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// do sends one request; it returns false for 204 No Content.
func (c *tokenModeChannel) do(ctx context.Context, method, path string, body, out any) (bool, error) {
	read := c.token
	if read == nil {
		read = func() (string, error) { return service.ReadToken(c.dataDir) }
	}
	token, err := read()
	if err != nil {
		return false, fmt.Errorf("servis henüz hazır değil: %w", err)
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return false, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return false, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return false, nil
	}
	reply, err := io.ReadAll(io.LimitReader(resp.Body, tokenModeMaxReply))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(reply, &e) == nil && e.Error != "" {
			return false, errors.New(e.Error)
		}
		return false, fmt.Errorf("servis yanıtı: %s", resp.Status)
	}
	if out == nil {
		return true, nil
	}
	return true, json.Unmarshal(reply, out)
}

func (c *tokenModeChannel) Trust(ctx context.Context) (winapp.TokenTrust, error) {
	var t panel.TrayAdminTrust
	if _, err := c.do(ctx, http.MethodGet, "/api/app/tray/admin-mode/trust", nil, &t); err != nil {
		return winapp.TokenTrust{}, err
	}
	if len(t.Root) != ed25519.PublicKeySize {
		return winapp.TokenTrust{}, errors.New("servis geçersiz kök anahtarı bildirdi")
	}
	return winapp.TokenTrust{NetworkID: t.NetworkID, Root: ed25519.PublicKey(t.Root), Revoked: t.Revoked}, nil
}

func (c *tokenModeChannel) Report(ctx context.Context, st winapp.TokenModeReport) error {
	body := panel.TrayAdminState{Open: st.Open, Offer: st.Offer, Role: st.Role, Name: st.Name, Key: st.Key, Reader: st.Reader,
		Started: st.Started, Ends: st.Ends, IdleUntil: st.IdleUntil, Reason: st.Reason}
	_, err := c.do(ctx, http.MethodPost, "/api/app/tray/admin-mode", body, nil)
	return err
}

func (c *tokenModeChannel) NextSign(ctx context.Context) (*winapp.TokenSignRequest, error) {
	var r panel.TraySignRequest
	ok, err := c.do(ctx, http.MethodGet, "/api/app/tray/admin-mode/next", nil, &r)
	if err != nil || !ok {
		return nil, err
	}
	if len(r.Payload) > trust.MaxDocumentSize || r.ID == "" {
		return nil, errors.New("geçersiz imza isteği")
	}
	return &winapp.TokenSignRequest{ID: r.ID, Context: r.Context, Payload: r.Payload, Version: r.Version, Summary: r.Summary}, nil
}

func (c *tokenModeChannel) SignResult(ctx context.Context, id string, sig []byte, reason string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/app/tray/admin-mode/result", panel.TraySignResult{ID: id, Signature: sig, Error: reason}, nil)
	return err
}
