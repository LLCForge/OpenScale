package panel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/sftpclient"
	"github.com/openscale/openscale/internal/sshclient"
)

// File browser next to the SSH terminal (#855, ADR-0203).
//
// POST /api/sftp/open signs in like the terminal (same device, port,
// account and the same pinned host key in ssh_known_hosts.json) and opens
// the "sftp" subsystem; the answer is a handle bound to the panel session.
// The other requests name that handle:
//
//	GET  /api/sftp/list?h=&path=     list a directory
//	POST /api/sftp/download {h,path} fetch a file into the quarantine
//	POST /api/sftp/upload?h=&dir=    store the body as dir/<name>
//	POST /api/sftp/mkdir {h,dir,name}
//	POST /api/sftp/remove {h,path,dir}
//	POST /api/sftp/close {h}
//
// Remote paths must be absolute and are cleaned; new names must be one
// path element. A download lands in this computer's quarantine folder
// with the operating system's "from another computer" mark and shows up
// on the Received Files page, where it is released like any received
// file. Uploads never replace an existing file. Only this computer's
// panel serves these requests, and a session closes after ten idle
// minutes or with the panel session.

const (
	sftpMaxSessions  = 8
	sftpIdle         = 10 * time.Minute
	sftpMaxTransfer  = MaxE2EUpload
	sftpTransferTime = 30 * time.Minute
	sftpOpTimeout    = 30 * time.Second
	sftpMaxRequest   = 8 << 10
)

type sftpSession struct {
	sessionID string
	device    string
	ssh       *sshclient.Client
	c         *sftpclient.Client
	home      string
	timer     *time.Timer
}

func (ss *sftpSession) close() {
	_ = ss.c.Close()
	_ = ss.ssh.Close()
}

// f3State is this file's per-server state; kept beside Server so the
// struct does not change.
type f3State struct {
	mu     sync.Mutex
	sftp   map[string]*sftpSession
	staged map[string]time.Time // tray send-to staging (f3_tray_api.go)
	// dial replaces sshclient.Dial in tests.
	dial func(ctx context.Context, cfg sshclient.Config) (*sshclient.Client, error)
}

var f3States sync.Map // *Server -> *f3State

func (s *Server) f3() *f3State {
	v, _ := f3States.LoadOrStore(s, &f3State{sftp: map[string]*sftpSession{}, staged: map[string]time.Time{}})
	return v.(*f3State)
}

func (s *Server) f3Routes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.localOnly(h)) }
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.localOnly(h))))
	}
	mux.HandleFunc("POST /api/sftp/open", write(s.handleSFTPOpen))
	mux.HandleFunc("GET /api/sftp/list", read(s.handleSFTPList))
	mux.HandleFunc("POST /api/sftp/download", write(s.handleSFTPDownload))
	mux.HandleFunc("POST /api/sftp/upload", write(s.handleSFTPUpload))
	mux.HandleFunc("POST /api/sftp/mkdir", write(s.handleSFTPMkdir))
	mux.HandleFunc("POST /api/sftp/remove", write(s.handleSFTPRemove))
	mux.HandleFunc("POST /api/sftp/close", write(s.handleSFTPClose))
	s.f3TrayRoutes(mux) // f3_tray_api.go
}

type sftpOpenRequest struct {
	Device string `json:"device"`
	Port   int    `json:"port,omitempty"`
	User   string `json:"user"`
	// Password is base64 so it decodes into bytes that can be wiped.
	Password []byte `json:"password"`
}

func sftpFail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

func (s *Server) handleSFTPOpen(w http.ResponseWriter, r *http.Request) {
	var req sftpOpenRequest
	if !decodeBody(w, r, &req) {
		return
	}
	defer wipe(req.Password)
	if req.Port == 0 {
		req.Port = sshDefaultPort
	}
	if req.Port < 1 || req.Port > 65535 || req.User == "" || len(req.User) > 64 || strings.ContainsAny(req.User, " /\\:\x00") ||
		len(req.Password) == 0 || len(req.Password) > rdeskMaxPassword {
		writeError(w, http.StatusBadRequest, "Cihaz, port, kullanıcı adı veya parola geçersiz.")
		return
	}
	addr, ok := s.resolveDevice(req.Device)
	if !ok {
		writeError(w, http.StatusNotFound, "Cihaz ağ belgesinde bulunamadı.")
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Oturum yok.")
		return
	}
	st := s.f3()
	st.mu.Lock()
	n := len(st.sftp)
	dial := st.dial
	st.mu.Unlock()
	if n >= sftpMaxSessions {
		sftpFail(w, http.StatusTooManyRequests, "too_many", "Çok fazla açık dosya oturumu; birini kapatıp yeniden deneyin.")
		return
	}
	target := netip.AddrPortFrom(addr, uint16(req.Port))
	key := target.Addr().String()
	if _, blocked := sshGuard.Blocked(key); blocked {
		sftpFail(w, http.StatusTooManyRequests, "blocked", "Çok fazla hatalı parola; bu cihaz için bir süre bekleyin.")
		return
	}
	kh, err := s.knownHosts()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if dial == nil {
		dial = sshclient.Dial
	}
	pw := append([]byte(nil), req.Password...)
	ctx, cancel := context.WithTimeout(r.Context(), sshAuthTimeout)
	defer cancel()
	client, err := dial(ctx, sshclient.Config{
		Addr: target, HostName: req.Device + ":" + strconv.Itoa(req.Port), User: req.User, KnownHosts: kh,
		Password: func() ([]byte, error) { return pw, nil },
	})
	wipe(pw)
	var changed *sshclient.HostKeyChangedError
	switch {
	case errors.As(err, &changed):
		s.logger.Warn("SSH host key changed; file browser refused", "device", req.Device)
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Sunucu anahtarı değişti; ortadaki saldırı olabilir. Beklenen bir değişiklikse kaydı silip yeniden deneyin.",
			"code": "host_key_changed", "pinned": changed.Pinned, "fingerprint": changed.Received})
		return
	case errors.Is(err, sshclient.ErrAuth):
		delay, _ := sshGuard.Failure(key)
		time.Sleep(delay)
		sftpFail(w, http.StatusUnauthorized, "auth_failed", "Kullanıcı adı veya parola kabul edilmedi.")
		return
	case err != nil:
		sftpFail(w, http.StatusBadGateway, "connect_failed", "Cihaza bağlanılamadı.")
		return
	}
	sshGuard.Success(key)
	rw, err := client.Subsystem("sftp")
	if err != nil {
		_ = client.Close()
		sftpFail(w, http.StatusBadGateway, "sftp_unavailable", "Cihazın SSH sunucusunda SFTP açık değil.")
		return
	}
	fc, err := sftpclient.New(ctx, rw)
	if err != nil {
		_ = client.Close()
		sftpFail(w, http.StatusBadGateway, "sftp_unavailable", "Cihazın SSH sunucusunda SFTP açık değil.")
		return
	}
	home, err := fc.RealPath(ctx, ".")
	if err != nil {
		home = "/"
	}
	if h, err := sftpclient.CleanAbs(home); err == nil {
		home = h
	} else {
		home = "/"
	}
	handle, err := randomToken(s.random)
	if err != nil {
		_ = fc.Close()
		_ = client.Close()
		writeError(w, http.StatusInternalServerError, "Bilet üretilemedi.")
		return
	}
	ss := &sftpSession{sessionID: c.Value, device: req.Device, ssh: client, c: fc, home: home}
	st.mu.Lock()
	if len(st.sftp) >= sftpMaxSessions {
		st.mu.Unlock()
		ss.close()
		sftpFail(w, http.StatusTooManyRequests, "too_many", "Çok fazla açık dosya oturumu; birini kapatıp yeniden deneyin.")
		return
	}
	st.sftp[handle] = ss
	ss.timer = time.AfterFunc(sftpIdle, func() {
		if old := s.takeSFTP(handle, ""); old != nil {
			old.close()
		}
	})
	st.mu.Unlock()
	s.logger.Info("SFTP file browser opened from the panel", "device", req.Device)
	writeJSON(w, http.StatusOK, map[string]any{"handle": handle, "home": home,
		"hostkey": map[string]string{"status": hostStatus(client.Host.Status), "fingerprint": client.Host.Fingerprint}})
}

// takeSFTP removes and returns the session of handle; an empty sessionID
// takes it regardless of the owner (idle expiry).
func (s *Server) takeSFTP(handle, sessionID string) *sftpSession {
	st := s.f3()
	st.mu.Lock()
	defer st.mu.Unlock()
	ss, ok := st.sftp[handle]
	if !ok || (sessionID != "" && ss.sessionID != sessionID) {
		return nil
	}
	delete(st.sftp, handle)
	ss.timer.Stop()
	return ss
}

// sftpFor returns the caller's session of handle and restarts its idle
// timer. A session whose connection ended is closed and refused.
func (s *Server) sftpFor(w http.ResponseWriter, r *http.Request, handle string) (*sftpSession, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || handle == "" || len(handle) > 128 {
		sftpFail(w, http.StatusNotFound, "no_session", "Dosya oturumu yok veya süresi doldu; yeniden bağlanın.")
		return nil, false
	}
	st := s.f3()
	st.mu.Lock()
	ss, ok := st.sftp[handle]
	if ok && ss.sessionID == c.Value {
		ss.timer.Reset(sftpIdle)
	}
	st.mu.Unlock()
	if !ok || ss.sessionID != c.Value {
		sftpFail(w, http.StatusNotFound, "no_session", "Dosya oturumu yok veya süresi doldu; yeniden bağlanın.")
		return nil, false
	}
	if ss.c.Err() != nil {
		if old := s.takeSFTP(handle, c.Value); old != nil {
			old.close()
		}
		sftpFail(w, http.StatusNotFound, "no_session", "Dosya oturumu kapandı; yeniden bağlanın.")
		return nil, false
	}
	return ss, true
}

// sftpError answers a failed remote operation without the server's text.
func sftpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sftpclient.ErrBadPath):
		sftpFail(w, http.StatusBadRequest, "bad_path", "Yol geçersiz.")
	case errors.Is(err, fs.ErrNotExist):
		sftpFail(w, http.StatusNotFound, "not_found", "Dosya veya klasör bulunamadı.")
	case errors.Is(err, fs.ErrPermission):
		sftpFail(w, http.StatusForbidden, "denied", "Bu hesabın bu işleme izni yok.")
	case errors.Is(err, sftpclient.ErrTooLarge):
		sftpFail(w, http.StatusRequestEntityTooLarge, "too_large", "Dosya çok büyük (en çok 2 GiB).")
	case errors.Is(err, sftpclient.ErrTooMany):
		sftpFail(w, http.StatusUnprocessableEntity, "too_many_entries", "Klasörde çok fazla girdi var.")
	case errors.Is(err, context.DeadlineExceeded):
		sftpFail(w, http.StatusGatewayTimeout, "timeout", "Cihaz zamanında yanıt vermedi.")
	default:
		var se *sftpclient.StatusError
		if errors.As(err, &se) {
			sftpFail(w, http.StatusConflict, "failed", "Cihaz işlemi yapamadı (zaten var, klasör boş değil veya desteklenmiyor olabilir).")
			return
		}
		sftpFail(w, http.StatusBadGateway, "failed", "İşlem tamamlanamadı; bağlantı kopmuş olabilir.")
	}
}

type sftpEntry struct {
	Name    string     `json:"name"`
	Size    int64      `json:"size"`
	Dir     bool       `json:"dir"`
	Link    bool       `json:"link"`
	Regular bool       `json:"regular"`
	Perm    uint32     `json:"perm"`
	ModTime *time.Time `json:"mtime,omitempty"`
}

func (s *Server) handleSFTPList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ss, ok := s.sftpFor(w, r, q.Get("h"))
	if !ok {
		return
	}
	p := q.Get("path")
	if p == "" {
		p = ss.home
	}
	clean, err := sftpclient.CleanAbs(p)
	if err != nil {
		sftpError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sftpOpTimeout)
	defer cancel()
	list, err := ss.c.ReadDir(ctx, clean)
	truncated := errors.Is(err, sftpclient.ErrTooMany)
	if err != nil && !truncated {
		sftpError(w, err)
		return
	}
	out := make([]sftpEntry, 0, len(list))
	for _, e := range list {
		v := sftpEntry{Name: e.Name, Size: e.Size, Dir: e.Dir, Link: e.Link, Regular: e.Regular, Perm: e.Perm}
		if !e.ModTime.IsZero() {
			t := e.ModTime
			v.ModTime = &t
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b sftpEntry) int {
		if a.Dir != b.Dir {
			if a.Dir {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	writeJSON(w, http.StatusOK, map[string]any{"path": clean, "home": ss.home, "entries": out, "truncated": truncated})
}

type sftpPathRequest struct {
	Handle string `json:"h"`
	Path   string `json:"path"`
	Dir    bool   `json:"dir,omitempty"`
}

type sftpMkdirRequest struct {
	Handle string `json:"h"`
	Dir    string `json:"dir"`
	Name   string `json:"name"`
}

// decodeSmall reads a small JSON body.
func decodeSmall(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, sftpMaxRequest)
	return decodeBody(w, r, v)
}

// extendDeadlines gives a long transfer room past the server's timeouts.
func extendDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	until := time.Now().Add(sftpTransferTime)
	_ = rc.SetReadDeadline(until)
	_ = rc.SetWriteDeadline(until)
}

func (s *Server) handleSFTPDownload(w http.ResponseWriter, r *http.Request) {
	var req sftpPathRequest
	if !decodeSmall(w, r, &req) {
		return
	}
	ss, ok := s.sftpFor(w, r, req.Handle)
	if !ok {
		return
	}
	clean, err := sftpclient.CleanAbs(req.Path)
	if err != nil {
		sftpError(w, err)
		return
	}
	files, ok := s.app.(E2EFileControl)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu bilgisayarda karantina klasörü yok; dosya indirilemez.")
		return
	}
	dir := files.E2EQuarantine().Dir
	if dir == "" {
		writeError(w, http.StatusNotFound, "Bu bilgisayarda karantina klasörü yok; dosya indirilemez.")
		return
	}
	extendDeadlines(w)
	ctx, cancel := context.WithTimeout(r.Context(), sftpTransferTime)
	defer cancel()
	fi, err := ss.c.Stat(ctx, clean)
	if err != nil {
		sftpError(w, err)
		return
	}
	if !fi.Regular {
		sftpFail(w, http.StatusBadRequest, "not_file", "Yalnızca normal dosyalar indirilebilir.")
		return
	}
	if fi.Size > sftpMaxTransfer {
		sftpError(w, sftpclient.ErrTooLarge)
		return
	}
	name, f, err := createQuarantined(dir, fi.Name)
	if err != nil {
		s.logger.Warn("SFTP download could not create the file", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "Dosya bu bilgisayara yazılamadı.")
		return
	}
	dst := filepath.Join(dir, name)
	n, err := ss.c.Download(ctx, clean, f, sftpMaxTransfer)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		sftpError(w, err)
		return
	}
	marked := filesend.MarkQuarantine(dst, "openscale:sftp:"+ss.device) == nil
	s.logger.Info("SFTP file downloaded into quarantine", "device", ss.device, "bytes", n)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "size": n, "quarantined": marked})
}

// createQuarantined creates a new file for the remote name in dir: the
// name is cleaned like a received file's and never replaces one.
func createQuarantined(dir, remote string) (string, *os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	clean, err := filesend.SanitizeName(remote)
	if err != nil {
		clean = "indirilen-dosya"
	}
	ext := filepath.Ext(clean)
	base := strings.TrimSuffix(clean, ext)
	for i := 0; i < 1000; i++ {
		cand := clean
		if i > 0 {
			cand = fmt.Sprintf("%s (%d)%s", base, i, ext)
		}
		f, err := os.OpenFile(filepath.Join(dir, cand), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return cand, f, nil
	}
	return "", nil, errors.New("çok fazla aynı adlı dosya")
}

func (s *Server) handleSFTPUpload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ss, ok := s.sftpFor(w, r, q.Get("h"))
	if !ok {
		return
	}
	raw := r.Header.Get(E2EFileNameHeader)
	name, err := url.PathUnescape(raw)
	if raw == "" || len(raw) > 1024 || err != nil {
		sftpFail(w, http.StatusBadRequest, "bad_name", "Dosya adı eksik veya geçersiz.")
		return
	}
	target, err := sftpclient.Join(q.Get("dir"), name)
	if err != nil {
		sftpFail(w, http.StatusBadRequest, "bad_name", "Dosya adı veya klasör geçersiz.")
		return
	}
	if r.ContentLength > sftpMaxTransfer {
		sftpError(w, sftpclient.ErrTooLarge)
		return
	}
	extendDeadlines(w)
	ctx, cancel := context.WithTimeout(r.Context(), sftpTransferTime)
	defer cancel()
	body := http.MaxBytesReader(w, r.Body, sftpMaxTransfer)
	n, err := ss.c.Upload(ctx, body, target, sftpMaxTransfer)
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		err = sftpclient.ErrTooLarge
	}
	if err != nil {
		sftpError(w, err)
		return
	}
	s.logger.Info("SFTP file uploaded from the panel", "device", ss.device, "bytes", n)
	writeJSON(w, http.StatusOK, map[string]any{"path": target, "size": n})
}

func (s *Server) handleSFTPMkdir(w http.ResponseWriter, r *http.Request) {
	var req sftpMkdirRequest
	if !decodeSmall(w, r, &req) {
		return
	}
	ss, ok := s.sftpFor(w, r, req.Handle)
	if !ok {
		return
	}
	target, err := sftpclient.Join(req.Dir, req.Name)
	if err != nil {
		sftpFail(w, http.StatusBadRequest, "bad_name", "Klasör adı geçersiz.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sftpOpTimeout)
	defer cancel()
	if err := ss.c.Mkdir(ctx, target); err != nil {
		sftpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": target})
}

func (s *Server) handleSFTPRemove(w http.ResponseWriter, r *http.Request) {
	var req sftpPathRequest
	if !decodeSmall(w, r, &req) {
		return
	}
	ss, ok := s.sftpFor(w, r, req.Handle)
	if !ok {
		return
	}
	clean, err := sftpclient.CleanAbs(req.Path)
	if err != nil || clean == "/" {
		sftpFail(w, http.StatusBadRequest, "bad_path", "Yol geçersiz.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sftpOpTimeout)
	defer cancel()
	fi, err := ss.c.Lstat(ctx, clean)
	if err != nil {
		sftpError(w, err)
		return
	}
	if fi.Dir != req.Dir {
		// The page asked about something else than what is there now.
		sftpFail(w, http.StatusConflict, "changed", "Öğe değişmiş; listeyi yenileyip yeniden deneyin.")
		return
	}
	if fi.Dir {
		err = ss.c.RemoveDir(ctx, clean)
	} else {
		err = ss.c.Remove(ctx, clean)
	}
	if err != nil {
		sftpError(w, err)
		return
	}
	s.logger.Info("SFTP item removed from the panel", "device", ss.device, "dir", fi.Dir)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSFTPClose(w http.ResponseWriter, r *http.Request) {
	var req sftpPathRequest
	if !decodeSmall(w, r, &req) {
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err == nil {
		if ss := s.takeSFTP(req.Handle, c.Value); ss != nil {
			ss.close()
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// closeAllSFTP ends every file session (tests and shutdown).
func (s *Server) closeAllSFTP() {
	st := s.f3()
	st.mu.Lock()
	list := make([]*sftpSession, 0, len(st.sftp))
	for k, ss := range st.sftp {
		ss.timer.Stop()
		list = append(list, ss)
		delete(st.sftp, k)
	}
	st.mu.Unlock()
	for _, ss := range list {
		ss.close()
	}
}
