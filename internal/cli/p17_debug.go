package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

// Debug HTTP page (F-202, ADR-0108). "openscale debug http" serves, only
// while it runs, a read-only page on 127.0.0.1 with the tunnel's state:
// status, health, paths (direct or relay), WireGuard peers (public keys
// only), events, preferences and the rules of this device's signed
// document. It reads through the same local API and rights as "openscale
// status" (ADR-0050); the address carries a random token and the page has
// no scripts. Nothing listens on the tunnel, so peers never see it.

const (
	debugHTTPDefault = 30 * time.Minute
	debugHTTPMax     = 8 * time.Hour
	debugCallTimeout = 10 * time.Second
)

// debugSection is one block of the page.
type debugSection struct {
	Title string
	Err   string
	Rows  [][]string
	Head  []string
}

type debugPage struct {
	Generated string
	Sections  []debugSection
}

var debugTemplate = template.Must(template.New("debug").Parse(`<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenScale hata ayıklama</title>
<style>
body{font-family:system-ui,sans-serif;background:#f6f7f6;color:#18201d;margin:0;padding:16px;line-height:1.5}
main{max-width:72rem;margin:0 auto}h1{font-size:1.25rem}h2{font-size:1rem;margin:24px 0 8px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:14px}th,td{border:1px solid #dfe3e1;padding:4px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#eef1ef}.err{color:#a3261b}p.meta{color:#4b5752;font-size:14px}a{color:#1d5c46}
</style></head><body><main>
<h1>OpenScale hata ayıklama</h1>
<p class="meta">Oluşturuldu: {{.Generated}} · yalnızca bu bilgisayardan · <a href="./">yenile</a></p>
{{range .Sections}}<section><h2>{{.Title}}</h2>
{{if .Err}}<p class="err">{{.Err}}</p>{{else}}<table>{{if .Head}}<tr>{{range .Head}}<th>{{.}}</th>{{end}}</tr>{{end}}
{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}</table>{{end}}</section>
{{end}}</main></body></html>`))

func cmdDebugHTTP(env *Env, args []string) error {
	fs := newFlagSet(env, "debug http")
	port := fs.Int("port", 0, "127.0.0.1 üzerindeki port; 0 boş bir port seçer")
	dur := fs.Duration("sure", debugHTTPDefault, "sayfanın açık kalacağı süre (en çok 8h)")
	stateDir := fs.String("state-dir", "", "'openscale up' durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *port < 0 || *port > 65535 || *dur <= 0 || *dur > debugHTTPMax {
		return usageError("--port 0-65535, --sure 0-8h olmalı")
	}
	lc, err := openLocalClient(env, *stateDir)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	var tok [32]byte
	if _, err := io.ReadFull(randomOr(env), tok[:]); err != nil {
		_ = ln.Close()
		return err
	}
	token := hex.EncodeToString(tok[:])
	host := ln.Addr().String()
	docDir := debugDocumentDir(env, *stateDir, lc.service)
	h := &debugHandler{env: env, lc: lc, host: host, prefix: "/d/" + token + "/", docDir: docDir}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	ctx, cancel := context.WithTimeout(envContext(env), *dur)
	defer cancel()
	fmt.Fprintf(env.Stdout, "Hata ayıklama sayfası (yalnızca bu bilgisayar, %s boyunca):\n  http://%s%s\nDurdurmak için Ctrl+C.\n", dur.String(), host, h.prefix)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, c2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer c2()
		_ = srv.Shutdown(sctx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func randomOr(env *Env) io.Reader {
	if env.Random != nil {
		return env.Random
	}
	return rand.Reader
}

// debugDocumentDir is where this device's signed document is kept.
func debugDocumentDir(env *Env, stateDir string, viaService bool) string {
	if viaService {
		if d := localAPI.dataDir(); d != "" {
			return filepath.Join(d, service.DeviceDir)
		}
	}
	dir, err := resolveStateDir(env, stateDir)
	if err != nil {
		return ""
	}
	return dir
}

type debugHandler struct {
	env    *Env
	lc     *localClient
	host   string
	prefix string
	docDir string
}

func (h *debugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'")
	// DNS rebinding: only the loopback address itself.
	_, port, _ := net.SplitHostPort(h.host)
	if r.Host != h.host && r.Host != net.JoinHostPort("localhost", port) {
		http.Error(w, "Geçersiz Host başlığı", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Yöntem desteklenmiyor", http.StatusMethodNotAllowed)
		return
	}
	if len(r.URL.Path) != len(h.prefix) || subtle.ConstantTimeCompare([]byte(r.URL.Path), []byte(h.prefix)) != 1 {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), debugCallTimeout)
	defer cancel()
	page := debugPage{Generated: h.env.Now().Format(time.RFC3339), Sections: h.sections(ctx)}
	hd.Set("Content-Type", "text/html; charset=utf-8")
	if err := debugTemplate.Execute(w, page); err != nil {
		http.Error(w, "Sayfa oluşturulamadı", http.StatusInternalServerError)
	}
}

func (h *debugHandler) get(ctx context.Context, path string, out any) string {
	if err := h.lc.call(ctx, http.MethodGet, panel.LocalAPIPrefix+path, nil, out); err != nil {
		return err.Error()
	}
	return ""
}

func (h *debugHandler) sections(ctx context.Context) []debugSection {
	var out []debugSection

	var st panel.DiagStatus
	sec := debugSection{Title: "Durum", Head: []string{"Alan", "Değer"}}
	if sec.Err = h.get(ctx, "/status", &st); sec.Err == "" {
		sec.Rows = append(sec.Rows, []string{"Kip", st.Mode}, []string{"Çalışıyor", fmt.Sprint(st.Running)}, []string{"Bağlı", fmt.Sprint(st.Connected)},
			[]string{"Arayüz", st.Interface}, []string{"Belge sürümü", fmt.Sprint(st.DocumentVersion)}, []string{"Çıkış düğümü", st.ExitNode})
		if st.Self != nil {
			sec.Rows = append(sec.Rows, []string{"Bu cihaz", st.Self.Name + " (" + st.Self.IPv4 + ")"})
		}
		if st.LastSync != nil {
			sec.Rows = append(sec.Rows, []string{"Son eşitleme", st.LastSync.Format(time.RFC3339)})
		}
		if st.LastSyncError != "" {
			sec.Rows = append(sec.Rows, []string{"Eşitleme hatası", st.LastSyncError})
		}
	}
	out = append(out, sec)

	var hr panel.HealthReport
	sec = debugSection{Title: "Sağlık", Head: []string{"Kod", "Düzey", "Açıklama"}}
	if sec.Err = h.get(ctx, "/health", &hr); sec.Err == "" {
		sec.Rows = append(sec.Rows, []string{"live/ready", "", fmt.Sprintf("live=%v ready=%v %s", hr.Live, hr.Ready, strings.Join(hr.Reasons, "; "))})
		for _, a := range hr.Alerts {
			sec.Rows = append(sec.Rows, []string{a.Code, a.Level, a.Message})
		}
	}
	out = append(out, sec)

	var paths struct {
		Peers []struct {
			Name     string `json:"name"`
			Endpoint string `json:"endpoint"`
			Relayed  bool   `json:"relayed"`
			Class    string `json:"class"`
			PQ       string `json:"post_quantum"`
		} `json:"peers"`
	}
	sec = debugSection{Title: "Yollar ve aktarıcı kullanan eşler", Head: []string{"Eş", "Yol", "Uç nokta", "Sınıf", "PSK"}}
	if sec.Err = h.get(ctx, "/paths", &paths); sec.Err == "" {
		for _, p := range paths.Peers {
			kind := "doğrudan"
			if p.Relayed {
				kind = "aktarıcı"
			}
			sec.Rows = append(sec.Rows, []string{p.Name, kind, p.Endpoint, p.Class, p.PQ})
		}
	}
	out = append(out, sec)

	var wg panel.WGShow
	sec = debugSection{Title: "WireGuard (yalnızca açık anahtarlar)", Head: []string{"Eş", "Açık anahtar", "İzinli adresler", "Son el sıkışma", "Alınan/gönderilen"}}
	if sec.Err = h.get(ctx, "/wg", &wg); sec.Err == "" {
		for _, p := range wg.Peers {
			hs := ""
			if p.LastHandshake != nil {
				hs = p.LastHandshake.Format(time.RFC3339)
			}
			sec.Rows = append(sec.Rows, []string{p.Name, p.PublicKey, strings.Join(p.AllowedIPs, ", "), hs, fmt.Sprintf("%d / %d", p.RxBytes, p.TxBytes)})
		}
	}
	out = append(out, sec)

	var ev struct {
		Events []panel.DiagEvent `json:"events"`
	}
	sec = debugSection{Title: "Son olaylar", Head: []string{"Zaman", "Tür", "Eş", "İleti"}}
	if sec.Err = h.get(ctx, "/events", &ev); sec.Err == "" {
		for _, e := range ev.Events {
			sec.Rows = append(sec.Rows, []string{e.At.Format(time.RFC3339), e.Kind, e.Peer, e.Message})
		}
	}
	out = append(out, sec)

	var prefs struct {
		Prefs []panel.Pref `json:"prefs"`
	}
	sec = debugSection{Title: "Ayarlar", Head: []string{"Anahtar", "Değer", "Varsayılan"}}
	if sec.Err = h.get(ctx, "/prefs", &prefs); sec.Err == "" {
		for _, p := range prefs.Prefs {
			sec.Rows = append(sec.Rows, []string{p.Key, p.Value, p.Default})
		}
	}
	out = append(out, sec)

	out = append(out, h.rulesSection())
	return out
}

// rulesSection lists the rules of this device's signed document.
func (h *debugHandler) rulesSection() debugSection {
	sec := debugSection{Title: "Kurallar (bu cihazın imzalı belgesi)", Head: []string{"#", "Eylem", "Kaynak", "Hedef", "Protokol/servis", "Portlar", "Durum"}}
	if h.docDir == "" {
		sec.Err = "belge klasörü bulunamadı"
		return sec
	}
	store, err := member.Open(h.docDir)
	if err != nil {
		sec.Err = "belge okunamadı: " + err.Error()
		return sec
	}
	doc := store.Document()
	if doc == nil {
		sec.Err = "belge yok"
		return sec
	}
	for i, r := range doc.Rules {
		action := string(r.Action)
		if action == "" {
			action = string(trust.RuleAllow)
		}
		proto := string(r.Protocol)
		if r.Service != "" {
			proto = "servis: " + string(r.Service)
		}
		state := "etkin"
		if r.Disabled {
			state = "devre dışı"
		}
		sec.Rows = append(sec.Rows, []string{fmt.Sprint(i + 1), action, strings.Join(r.From, ", "), strings.Join(r.To, ", "), proto, strings.Join(r.Ports, ", "), state})
	}
	return sec
}
