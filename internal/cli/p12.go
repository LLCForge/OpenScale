package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"text/template"

	"github.com/openscale/openscale/internal/errcode"
)

// Observability and command line experience (P12): stable error codes and
// "openscale explain" (#550, ADR-0165), template output (#552), the
// readable network report (#553), encrypted diagnostics bundles (#512),
// traffic and resource history (#505, #516), the terminal interface
// (#551) and the MQTT publisher (#561, ADR-0167).

func p12Commands() []command {
	return []command{
		{"explain", "Hata kodunu çevrimdışı açıklar: <kod> | --list | --search <kelime> [--json]", cmdExplain},
		{"network report", "Ağın anahtarsız, okunur raporu (Markdown veya HTML): --dir ./ag [--html] [--out dosya]", cmdNetworkReport},
		{"debug bundle-key", "Teşhis paketi alıcı anahtarı üretir (yardım eden kişi çalıştırır): --out dosya", cmdBundleKey},
		{"debug bundle-open", "Alıcı anahtarına şifrelenmiş teşhis paketini açar: --key dosya -o paket.zip <paket.osb>", cmdBundleOpen},
		{"traffic history", "Cihaz başına saatlik trafik geçmişi (yalnızca toplam bayt, 30 gün): [cihaz] [--hours 24]", cmdTrafficHistory},
		{"resources", "OpenScale'in kendi işlemci, bellek ve pil kullanımı (son 24 saat)", cmdResources},
		{"tui", "Terminal arayüzü: durum, eşler, çıkış seçimi ve olaylar (panel gerekmez)", cmdTUI},
		{"mqtt", "Yerel MQTT aracısına durum ve olay yayımlar: init | show | test | run | off", cmdMQTT},
	}
}

// errorCodeLine is printed under an error that has a stable code.
func errorCodeLine(err error) string {
	return errcode.Suffix(errcode.Classify(err))
}

func cmdExplain(env *Env, args []string) error {
	fs := newFlagSet(env, "explain")
	list := fs.Bool("list", false, "bütün kodları listele")
	search := fs.String("search", "", "kod, başlık ve açıklamada kelime ara")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	// The code may come before or after the flags.
	var codes []string
	rest := fs.Args()
	for len(rest) > 0 {
		codes = append(codes, rest[0])
		if err := fs.Parse(rest[1:]); err != nil {
			return usageError("%v", err)
		}
		rest = fs.Args()
	}
	w := env.Stdout
	switch {
	case len(codes) > 1:
		return usageError("tek bir kod yazın")
	case len(codes) == 1:
		if *list || *search != "" {
			return usageError("kod ile --list veya --search birlikte kullanılmaz")
		}
		e, ok := errcode.Lookup(codes[0])
		if !ok {
			if errcode.Normalize(codes[0]) == "" {
				return usageError("kod OS-1234 biçiminde olmalı")
			}
			return fmt.Errorf("%s bilinmeyen bir kod; liste için: openscale explain --list", errcode.Normalize(codes[0]))
		}
		if *asJSON {
			return printJSON(w, struct {
				Schema int `json:"schema"`
				errcode.Entry
			}{1, e})
		}
		printExplain(w, e)
		return nil
	case *list || *search != "":
		entries := errcode.All()
		if *search != "" {
			if len(*search) > 200 {
				return usageError("arama en fazla 200 karakter")
			}
			entries = errcode.Search(*search)
		}
		if *asJSON {
			return printJSON(w, struct {
				Schema  int             `json:"schema"`
				Catalog int             `json:"catalog"`
				Codes   []errcode.Entry `json:"codes"`
			}{1, errcode.CatalogVersion, entries})
		}
		if len(entries) == 0 {
			fmt.Fprintln(w, "Eşleşen kod yok.")
			return nil
		}
		for _, e := range entries {
			fmt.Fprintf(w, "%s  %-12s %s\n", e.Code, e.Area, e.Title)
		}
		return nil
	}
	return usageError("bir kod yazın (ör. openscale explain OS-3001) veya --list kullanın")
}

func printExplain(w io.Writer, e errcode.Entry) {
	fmt.Fprintf(w, "%s: %s\n", e.Code, e.Title)
	if e.Deprecated {
		fmt.Fprintln(w, "(Bu kod artık oluşmuyor; eski mesajlar için tutuluyor.)")
	}
	fmt.Fprintf(w, "\nNeden: %s\n\nNe yapmalı:\n", e.Cause)
	for i, s := range e.Steps {
		fmt.Fprintf(w, "  %d. %s\n", i+1, s)
	}
	if len(e.Commands) > 0 {
		fmt.Fprintln(w, "\nBakılacak komutlar:")
		for _, c := range e.Commands {
			fmt.Fprintf(w, "  %s\n", c)
		}
	}
	fmt.Fprintf(w, "\nAyrıntı: docs/%s\n", e.Doc)
}

// ----- --format (#552) -----

// maxFormatLen bounds a template given on the command line.
const maxFormatLen = 4 << 10

// extractFormat removes "--format <şablon>" or "--format=<şablon>" from
// args (before a "--" only). found reports whether it was given.
func extractFormat(args []string) (tmpl string, rest []string, found bool, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		var val string
		switch {
		case a == "--format" || a == "-format":
			if i+1 >= len(args) {
				return "", nil, true, usageError("--format bir şablon ister, ör. --format '{{.version}}'")
			}
			val = args[i+1]
			rest = append(append([]string(nil), args[:i]...), args[i+2:]...)
		case strings.HasPrefix(a, "--format=") || strings.HasPrefix(a, "-format="):
			val = a[strings.IndexByte(a, '=')+1:]
			rest = append(append([]string(nil), args[:i]...), args[i+1:]...)
		default:
			continue
		}
		if val == "" || len(val) > maxFormatLen {
			return "", nil, true, usageError("--format şablonu 1-%d karakter olmalı", maxFormatLen)
		}
		return val, rest, true, nil
	}
	return "", args, false, nil
}

// withJSONFlag inserts --json after the command name unless it is
// already there. Commands with sub commands take --json after the sub
// command; the owner writes it there and --format leaves it alone.
func withJSONFlag(args []string) []string {
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "--json" || a == "-json" || strings.HasPrefix(a, "--json=") || strings.HasPrefix(a, "-json=") {
			return args
		}
	}
	start := 0
	if len(args) > 0 && (args[0] == "--network" || args[0] == "-network") {
		start = 2
	} else if len(args) > 0 && (strings.HasPrefix(args[0], "--network=") || strings.HasPrefix(args[0], "-network=")) {
		start = 1
	}
	if start > len(args) {
		return args
	}
	name := 0
	for _, c := range commands() {
		parts := strings.Fields(c.name)
		if len(args)-start >= len(parts) && strings.Join(args[start:start+len(parts)], " ") == c.name && len(parts) > name {
			name = len(parts)
		}
	}
	if name == 0 {
		if len(args) > start && args[start] == "version" {
			name = 1
		} else {
			return args
		}
	}
	at := start + name
	out := append(append(append([]string(nil), args[:at]...), "--json"), args[at:]...)
	return out
}

// formatFuncs are the template helpers.
var formatFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"join": func(sep string, v any) string {
		items, ok := v.([]any)
		if !ok {
			return fmt.Sprint(v)
		}
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = fmt.Sprint(it)
		}
		return strings.Join(parts, sep)
	},
	"pad": func(width int, v any) string {
		s := fmt.Sprint(v)
		if width > 200 {
			width = 200
		}
		for n := len([]rune(s)); n < width; n++ {
			s += " "
		}
		return s
	},
	"default": func(def string, v any) any {
		if v == nil || v == "" {
			return def
		}
		return v
	},
}

// parseFormat compiles a --format template.
func parseFormat(text string) (*template.Template, error) {
	// "json" is a shorthand for the whole value on one line.
	switch text {
	case "json":
		text = "{{json .}}"
	}
	t, err := template.New("format").Funcs(formatFuncs).Option("missingkey=zero").Parse(text)
	if err != nil {
		return nil, usageError("--format şablonu geçersiz: %v", err)
	}
	return t, nil
}

// formatWriter decodes the JSON values a command writes and renders each
// one with the template, so streaming commands (events --follow) work.
type formatWriter struct {
	pw   *io.PipeWriter
	done chan error
}

func newFormatWriter(t *template.Template, out io.Writer) *formatWriter {
	pr, pw := io.Pipe()
	f := &formatWriter{pw: pw, done: make(chan error, 1)}
	go func() {
		dec := json.NewDecoder(pr)
		dec.UseNumber()
		var err error
		for {
			var v any
			if err = dec.Decode(&v); err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				} else {
					err = fmt.Errorf("--format: komut çıktısı JSON değil: %w", err)
				}
				break
			}
			var b bytes.Buffer
			if err = t.Execute(&b, v); err != nil {
				err = fmt.Errorf("--format şablonu çalıştırılamadı: %w", err)
				break
			}
			if b.Len() == 0 || b.Bytes()[b.Len()-1] != '\n' {
				b.WriteByte('\n')
			}
			if _, err = out.Write(b.Bytes()); err != nil {
				break
			}
		}
		// Unblock the command if it is still writing.
		_ = pr.CloseWithError(errFormatStopped)
		f.done <- err
	}()
	return f
}

var errFormatStopped = errors.New("--format çıktısı durdu")

func (f *formatWriter) Write(p []byte) (int, error) { return f.pw.Write(p) }

func (f *formatWriter) finish() error {
	_ = f.pw.Close()
	return <-f.done
}

// runFormatted runs a command with --json and renders its output with the
// template; the exit code is the command's, or exitError when the output
// could not be rendered.
func runFormatted(env *Env, args []string, tmplText string) int {
	t, err := parseFormat(tmplText)
	if err != nil {
		fmt.Fprintf(env.Stderr, "hata: %v\n", err)
		return exitUsage
	}
	fw := newFormatWriter(t, env.Stdout)
	e := *env
	var mu sync.Mutex
	e.Stdout = lockedWriter{w: fw, mu: &mu}
	code := Run(withJSONFlag(args), &e)
	if err := fw.finish(); err != nil {
		fmt.Fprintf(env.Stderr, "hata: %v\n", err)
		if code == exitOK {
			return exitError
		}
	}
	return code
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
