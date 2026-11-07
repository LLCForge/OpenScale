package cli

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
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/winapp"
)

// The command line reaches a running tunnel through the loopback API of
// the desktop service (app token, readable only by administrators) or of a
// foreground "openscale up" (token in the state directory, readable only
// by the user who started it).

const (
	// localAPIFile tells other commands where "openscale up" serves its
	// diagnostics API.
	localAPIFile      = "local-api.json"
	maxLocalAPIFile   = 4 << 10
	localCallTimeout  = 20 * time.Second
	localProbeTimeout = 2 * time.Second
	maxLocalReply     = 1 << 20
)

// localAPIInfo is the content of localAPIFile.
type localAPIInfo struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

// localAPIOps are the side effects of finding the API; tests replace them.
type localAPIOps struct {
	dataDir     func() string
	readToken   func(dataDir string) (string, error)
	serviceBase string
}

var localAPI = localAPIOps{
	dataDir:     winapp.DataDir,
	readToken:   service.ReadToken,
	serviceBase: "http://127.0.0.1:" + strconv.Itoa(service.DefaultPanelPort),
}

// errNoLocalAPI explains how to reach the tunnel.
var errNoLocalAPI = errors.New("çalışan bir OpenScale tüneli bulunamadı. Windows'ta OpenScale servisi çalışıyor olmalı ve komut yönetici olarak (Yönetici: PowerShell) çalıştırılmalı; Linux'ta önce aynı kullanıcıyla 'openscale up' çalıştırın (farklı klasörse --state-dir verin)")

// apiError is an error answer of the API.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

type localClient struct {
	base    string
	token   string
	service bool
	http    *http.Client
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: localCallTimeout,
		// Loopback only; never through a proxy and never redirected.
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// openLocalClient finds the service's or a foreground tunnel's API.
// stateDir is the --state-dir of the command ("" for the default).
func openLocalClient(env *Env, stateDir string) (*localClient, error) {
	var serviceErr error
	if dir := localAPI.dataDir(); dir != "" {
		token, err := localAPI.readToken(dir)
		switch {
		case err == nil:
			c := &localClient{base: localAPI.serviceBase, token: token, service: true, http: newHTTPClient()}
			if c.reachable(envContext(env)) {
				return c, nil
			}
			serviceErr = errors.New("OpenScale servisi çalışmıyor; tepsi simgesinden veya Hizmetler'den başlatın")
		case errors.Is(err, fs.ErrPermission):
			serviceErr = errors.New("servisin anahtarı okunamadı: komutu yönetici olarak çalıştırın (Yönetici: PowerShell)")
		}
	}
	if c, err := openUpClient(env, stateDir); err == nil {
		return c, nil
	}
	if serviceErr != nil {
		return nil, serviceErr
	}
	return nil, errNoLocalAPI
}

func openUpClient(env *Env, stateDir string) (*localClient, error) {
	dir, err := resolveStateDir(env, stateDir)
	if err != nil {
		return nil, err
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, localAPIFile), maxLocalAPIFile)
	if err != nil {
		return nil, err
	}
	var info localAPIInfo
	if err := json.Unmarshal(data, &info); err != nil || info.Port < 1 || info.Port > 65535 || len(info.Token) < 32 {
		return nil, errors.New("local API file is corrupt")
	}
	c := &localClient{base: "http://127.0.0.1:" + strconv.Itoa(info.Port), token: info.Token, http: newHTTPClient()}
	if !c.reachable(envContext(env)) {
		return nil, errNoLocalAPI
	}
	return c, nil
}

// reachable asks the API for its health with a short timeout.
func (c *localClient) reachable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, localProbeTimeout)
	defer cancel()
	var h panel.HealthReport
	return c.call(ctx, http.MethodGet, panel.LocalAPIPrefix+"/health", nil, &h) == nil
}

// call sends one request; path includes the API prefix.
func (c *localClient) call(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("tünelin yerel API'sine ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxLocalReply))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(reply, &e) == nil && e.Error != "" {
			return &apiError{status: resp.StatusCode, msg: e.Error}
		}
		return &apiError{status: resp.StatusCode, msg: "yerel API yanıtı: " + resp.Status}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(reply, out)
}

// get and post call the diagnostics API.
func (c *localClient) get(env *Env, path string, out any) error {
	return c.call(envContext(env), http.MethodGet, panel.LocalAPIPrefix+path, nil, out)
}

func (c *localClient) post(env *Env, path string, body, out any) error {
	if body == nil {
		body = struct{}{}
	}
	return c.call(envContext(env), http.MethodPost, panel.LocalAPIPrefix+path, body, out)
}

// queryEscape builds a query string value.
func queryEscape(s string) string { return url.QueryEscape(s) }
