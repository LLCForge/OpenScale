package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// openscale prompt (#863): a short status for the shell prompt. It must
// never slow the prompt down: a fresh answer comes from a small per-user
// cache file, otherwise from the running tunnel's loopback API within a
// few milliseconds. When neither answers in time it prints nothing and
// exits with 0, so a stopped service leaves the prompt as it was.

const (
	defaultPromptTimeout = 50 * time.Millisecond
	maxPromptTimeout     = 2 * time.Second
	promptCacheTTL       = 2 * time.Second
	promptCacheFile      = "prompt-cache.json"
	maxPromptCache       = 4 << 10
	maxPromptOutput      = 256
	defaultPromptFormat  = `{{if .Connected}}os:{{.State}}{{if .Exit}} çıkış:{{.Exit}}{{end}}{{if .Warnings}} !{{.Warnings}}{{end}}{{else}}os:{{.State}}{{end}}`
)

func init() {
	registerCommands(command{"prompt", "Kabuk istemi için kısa durum: bağlı mı, çıkış düğümü, uyarı sayısı [--json | --format şablon] (servis yanıt vermezse boş)", cmdPrompt})
}

// promptInfo is what a prompt template sees. It holds no secret; the cache
// file stores exactly this.
type promptInfo struct {
	// Connected is true while the tunnel runs.
	Connected bool `json:"connected"`
	// State is "bağlı", "koordinatörsüz" (running, last sync failed) or
	// "kapalı".
	State    string `json:"state"`
	Exit     string `json:"exit,omitempty"`
	Warnings int    `json:"warnings"`
	Device   string `json:"device,omitempty"`
	Version  uint64 `json:"version"`
	// At is when the answer was read from the tunnel.
	At time.Time `json:"at"`
}

// promptCacheDir is the per-user cache directory; tests replace it.
var promptCacheDir = func() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "OpenScale"), nil
}

func promptInfoOf(st panel.DiagStatus, now time.Time) promptInfo {
	p := promptInfo{Connected: st.Running, State: "kapalı", Exit: st.ExitNode, Warnings: len(st.Health), Version: st.DocumentVersion, At: now.UTC()}
	switch {
	case st.Running && st.LastSyncError != "":
		p.State = "koordinatörsüz"
	case st.Running:
		p.State = "bağlı"
	}
	if st.Self != nil {
		p.Device = st.Self.Name
	}
	return p
}

func cmdPrompt(env *Env, args []string) error {
	fs := newFlagSet(env, "prompt")
	asJSON := fs.Bool("json", false, "JSON çıktı; genel --format şablonu bunu kullanır (alanlar: .connected .state .exit .warnings .device .version)")
	timeout := fs.Duration("timeout", defaultPromptTimeout, "tünele sorma süresi (en çok 2s); dolarsa hiçbir şey yazılmaz")
	stateDir := fs.String("state-dir", "", "'openscale up' durum klasörü (Linux ve sunucular)")
	noCache := fs.Bool("no-cache", false, "önbelleği kullanma, her seferinde tünele sor")
	fs.Usage = func() { printPromptUsage(env, fs) }
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > maxPromptTimeout {
		return usageError("--timeout 0 ile %s arasında olmalı", maxPromptTimeout)
	}

	now := env.Now()
	info, ok := promptFromCache(now, *noCache, *stateDir)
	if !ok {
		info, ok = promptFromTunnel(env, *stateDir, *timeout, now)
		if !ok {
			return nil // service did not answer in time: print nothing
		}
		if !*noCache {
			writePromptCache(info, *stateDir)
		}
	}
	if *asJSON {
		return json.NewEncoder(env.Stdout).Encode(info)
	}
	var out bytes.Buffer
	if err := defaultPromptTemplate.Execute(&out, info); err != nil {
		return err
	}
	fmt.Fprint(env.Stdout, promptText(out.String()))
	return nil
}

// defaultPromptTemplate renders the text without --format.
var defaultPromptTemplate = template.Must(template.New("prompt").Parse(defaultPromptFormat))

// promptText keeps the prompt on one line and short, cutting on a rune.
func promptText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxPromptOutput {
		return s
	}
	cut := 0
	for i := range s {
		if i > maxPromptOutput {
			break
		}
		cut = i
	}
	return s[:cut]
}

// promptCachePath keys the cache by the state directory, so two tunnels
// on one computer do not share an answer.
func promptCachePath(stateDir string) (string, error) {
	dir, err := promptCacheDir()
	if err != nil || dir == "" {
		return "", errors.New("no cache directory")
	}
	name := promptCacheFile
	if stateDir != "" {
		sum := sha256.Sum256([]byte(filepath.Clean(stateDir)))
		name = "prompt-cache-" + hex.EncodeToString(sum[:8]) + ".json"
	}
	return filepath.Join(dir, name), nil
}

func promptFromCache(now time.Time, skip bool, stateDir string) (promptInfo, bool) {
	if skip {
		return promptInfo{}, false
	}
	path, err := promptCachePath(stateDir)
	if err != nil {
		return promptInfo{}, false
	}
	data, err := securefile.ReadPrivate(path, maxPromptCache)
	if err != nil {
		return promptInfo{}, false
	}
	var p promptInfo
	if json.Unmarshal(data, &p) != nil || p.State == "" {
		return promptInfo{}, false
	}
	age := now.Sub(p.At)
	if age < 0 || age > promptCacheTTL {
		return promptInfo{}, false
	}
	return p, true
}

func writePromptCache(p promptInfo, stateDir string) {
	path, err := promptCachePath(stateDir)
	if err != nil {
		return
	}
	data, err := json.Marshal(p)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	// Best effort: a prompt never fails because the cache cannot be written.
	_ = securefile.Replace(path, data)
}

// promptFromTunnel asks the service's or a foreground tunnel's API for its
// status within timeout. It skips the health probe of openLocalClient,
// which would wait far longer than a prompt may.
func promptFromTunnel(env *Env, stateDir string, timeout time.Duration, now time.Time) (promptInfo, bool) {
	ctx, cancel := context.WithTimeout(envContext(env), timeout)
	defer cancel()
	for _, c := range promptClients(env, stateDir) {
		var st panel.DiagStatus
		if err := c.call(ctx, http.MethodGet, panel.LocalAPIPrefix+"/status", nil, &st); err == nil {
			return promptInfoOf(st, now), true
		}
		if ctx.Err() != nil {
			break
		}
	}
	return promptInfo{}, false
}

// promptClients lists the APIs to ask, without contacting any of them.
func promptClients(env *Env, stateDir string) []*localClient {
	var out []*localClient
	if stateDir == "" {
		if dir := localAPI.dataDir(); dir != "" {
			if token, err := localAPI.readToken(dir); err == nil {
				out = append(out, &localClient{base: localAPI.serviceBase, token: token, service: true, http: newHTTPClient()})
			}
		}
	}
	dir, err := resolveStateDir(env, stateDir)
	if err != nil {
		return out
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, localAPIFile), maxLocalAPIFile)
	if err != nil {
		return out
	}
	var info localAPIInfo
	if json.Unmarshal(data, &info) != nil || info.Port < 1 || info.Port > 65535 || len(info.Token) < 32 {
		return out
	}
	return append(out, &localClient{base: fmt.Sprintf("http://127.0.0.1:%d", info.Port), token: info.Token, http: newHTTPClient()})
}

func printPromptUsage(env *Env, fs *flag.FlagSet) {
	w := env.Stderr
	fmt.Fprintln(w, "Kullanım: openscale prompt [--json | --format şablon] [--timeout 50ms]")
	fmt.Fprintln(w, "\nTünelin kısa durumunu yazar; servis yanıt vermezse hiçbir şey yazmaz ve beklemez.")
	fmt.Fprintln(w, "Varsayılan çıktı örnekleri: 'os:bağlı çıkış:vps !2', 'os:kapalı'.")
	fmt.Fprintln(w, "\nŞablon örneği: openscale prompt --format '{{if .connected}}[{{.device}}{{if .exit}} > {{.exit}}{{end}}]{{end}}'")
	fmt.Fprintln(w, "Alanlar: .connected .state .exit .warnings .device .version")
	fmt.Fprintln(w, "\nKurulum (istemin başına ekler):")
	fmt.Fprintln(w, "  bash  (~/.bashrc):   PS1='$(openscale prompt 2>/dev/null) '\"$PS1\"")
	fmt.Fprintln(w, "  zsh   (~/.zshrc):    setopt PROMPT_SUBST; PROMPT='$(openscale prompt 2>/dev/null) '$PROMPT")
	fmt.Fprintln(w, "  fish  (config.fish): functions -c fish_prompt _os_orig; function fish_prompt; echo -n (openscale prompt 2>/dev/null)' '; _os_orig; end")
	fmt.Fprintln(w, "  PowerShell ($PROFILE): $function:_osOrig = $function:prompt; function prompt { \"$(openscale prompt 2>$null) \" + (& $function:_osOrig) }")
	fmt.Fprintln(w, "\nWindows'ta servisin durumunu okumak yönetici yetkisi ister; yetki yoksa çıktı boş kalır.")
	fmt.Fprintln(w, "\nSeçenekler:")
	fs.PrintDefaults()
}
