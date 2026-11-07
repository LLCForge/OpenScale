// Package containers reads the labels of the containers running on this
// computer and turns "openscale.serve" labels into publishing suggestions
// (#441). It only lists containers (one read-only request to the local
// Docker or Podman API socket); it never starts, stops or changes one,
// and a suggestion is only a suggestion: publishing still needs the
// owner's serve configuration and a root-signed rule.
package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Labels read from containers.
const (
	LabelName = "openscale.serve"
	LabelPort = "openscale.serve.port"
	LabelType = "openscale.serve.type"
)

const (
	maxResponse    = 4 << 20
	requestTimeout = 5 * time.Second
	maxContainers  = 1000
)

// ErrUnsupported is returned where no local container API socket exists.
var ErrUnsupported = errors.New("containers: bu sistemde konteyner API soketi bulunamadı")

// Suggestion is one container that asks to be published.
type Suggestion struct {
	Container string `json:"container"`
	Image     string `json:"image,omitempty"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	// Target is the published host address of the container port, for
	// the serve configuration.
	Target string `json:"target,omitempty"`
	// Problem explains why the label cannot be used as it is.
	Problem string `json:"problem,omitempty"`
}

type apiPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type apiContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	Ports  []apiPort         `json:"Ports"`
}

// Sockets returns the API sockets to try, in order.
func Sockets() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var out []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(d) {
		out = append(out, filepath.Join(d, "docker.sock"), filepath.Join(d, "podman", "podman.sock"))
	}
	return append(out, "/var/run/docker.sock", "/run/podman/podman.sock")
}

// validName mirrors the serve service name rule (a DNS label).
func validName(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// suggest turns the listed containers into suggestions.
func suggest(list []apiContainer) []Suggestion {
	var out []Suggestion
	for _, c := range list {
		name, ok := c.Labels[LabelName]
		if !ok {
			continue
		}
		s := Suggestion{Container: strings.TrimPrefix(firstName(c), "/"), Image: c.Image, Name: strings.ToLower(strings.TrimSpace(name)), Type: "http"}
		if t := strings.ToLower(strings.TrimSpace(c.Labels[LabelType])); t != "" {
			s.Type = t
		}
		switch {
		case !validName(s.Name):
			s.Problem = "etiketteki ad küçük harf, rakam ve '-' içeren bir DNS etiketi olmalı"
		case s.Type != "http" && s.Type != "tcp":
			s.Problem = "tür http veya tcp olmalı"
		default:
			s.Target, s.Problem = target(c, s.Type)
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Suggestion) int { return strings.Compare(a.Name+a.Container, b.Name+b.Container) })
	return out
}

func firstName(c apiContainer) string {
	if len(c.Names) > 0 {
		return c.Names[0]
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

// target finds the host port the container port is published on.
func target(c apiContainer, typ string) (string, string) {
	want := 0
	if p := strings.TrimSpace(c.Labels[LabelPort]); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "port etiketi 1-65535 arasında bir sayı olmalı"
		}
		want = n
	}
	var tcp []apiPort
	for _, p := range c.Ports {
		if p.Type == "tcp" && p.PublicPort > 0 && (want == 0 || p.PrivatePort == want) {
			tcp = append(tcp, p)
		}
	}
	if len(tcp) == 0 {
		return "", "konteyner portu bu bilgisayarda yayımlanmamış (ör. -p 127.0.0.1:8080:80)"
	}
	ports := map[int]bool{}
	for _, p := range tcp {
		ports[p.PrivatePort] = true
	}
	if want == 0 && len(ports) > 1 {
		return "", "birden çok port yayımlanmış; openscale.serve.port etiketiyle birini seçin"
	}
	p := tcp[0]
	host := "127.0.0.1"
	if p.IP != "" && p.IP != "0.0.0.0" && p.IP != "::" {
		host = p.IP
	}
	hp := net.JoinHostPort(host, strconv.Itoa(p.PublicPort))
	if typ == "tcp" {
		return hp, ""
	}
	return "http://" + hp, ""
}

// List asks the API at socket (a Unix socket path) for the running
// containers and returns the suggestions.
func List(ctx context.Context, socket string) ([]Suggestion, error) {
	if !filepath.IsAbs(socket) {
		return nil, ErrUnsupported
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("containers: API soketine bağlanılamadı (izin veya servis): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("containers: API %d döndürdü", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponse {
		return nil, errors.New("containers: API yanıtı çok büyük")
	}
	var list []apiContainer
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, errors.New("containers: API yanıtı okunamadı")
	}
	if len(list) > maxContainers {
		list = list[:maxContainers]
	}
	return suggest(list), nil
}

// Discover tries the known sockets and returns the first answer.
func Discover(ctx context.Context) ([]Suggestion, string, error) {
	for _, s := range Sockets() {
		if info, err := os.Stat(s); err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		out, err := List(ctx, s)
		return out, s, err
	}
	return nil, "", ErrUnsupported
}
