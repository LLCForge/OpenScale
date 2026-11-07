package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

// Diagnostics bundle (F-194, #189). The service only gathers the content;
// the command line shows it to the owner and writes the zip on this
// computer after the owner confirms. Nothing is sent anywhere. Every file
// passes the log masking: IP addresses are shortened, key-like values and
// PEM blocks removed, and settings named like secrets dropped.

const (
	// maxBundleFile bounds one file; maxBundle the whole bundle.
	maxBundleFile = 256 << 10
	maxBundle     = 8 << 20
	// bundleCommandTimeout bounds one system command.
	bundleCommandTimeout = 10 * time.Second
)

// Scrub masks a text for the bundle.
func Scrub(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	s = privacy.RedactSecrets(privacy.MaskText(s))
	// MAC addresses keep only the maker prefix (OUI).
	s = macRe.ReplaceAllString(s, "$1$2$3$2$4$2**$2**$2**")
	return macSpacedRe.ReplaceAllString(s, "$1 $2 $3 ** ** **")
}

var (
	macRe       = regexp.MustCompile(`\b([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}\b`)
	macSpacedRe = regexp.MustCompile(`\b([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{2}) [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2}\b`)
)

// scrubLines masks text line by line; MaskText bounds the length of one
// value, so long outputs are masked in pieces.
func scrubLines(s string) string {
	var b strings.Builder
	for line := range strings.Lines(s) {
		b.WriteString(Scrub(line))
	}
	return b.String()
}

// RedactJSON removes values whose key names a secret from a JSON document
// and masks the rest; data that is not JSON is only masked.
func RedactJSON(data []byte) string {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return scrubLines(string(data))
	}
	v = redactValue(v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return scrubLines(string(out))
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if privacy.IsSecretKey(k) {
				t[k] = privacy.Redacted
				continue
			}
			t[k] = redactValue(x)
		}
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
	}
	return v
}

type bundleBuilder struct {
	files []panel.BundleFile
	size  int
}

func (b *bundleBuilder) add(name, content string) {
	if len(content) > maxBundleFile {
		content = content[len(content)-maxBundleFile:]
		if i := strings.IndexByte(content, '\n'); i >= 0 {
			content = content[i+1:]
		}
		content = "(dosyanın yalnızca son kısmı)\n" + content
	}
	if b.size+len(content) > maxBundle {
		content = "(teşhis paketi boyut sınırına ulaştı; bu dosya eklenmedi)\n"
	}
	b.size += len(content)
	b.files = append(b.files, panel.BundleFile{Name: name, Content: content})
}

func (b *bundleBuilder) addJSON(name string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		b.add(name, "kodlanamadı: "+err.Error()+"\n")
		return
	}
	b.add(name, RedactJSON(data)+"\n")
}

// runForBundle runs a read-only system tool, found only in the system
// folders (never through PATH, F-125), and returns its masked output or
// the error.
func runForBundle(ctx context.Context, tool string, args ...string) string {
	exe, err := bundleTool(tool)
	if err != nil {
		return scrubLines("$ " + tool + " " + strings.Join(args, " ") + "\n(" + err.Error() + ")\n")
	}
	ctx, cancel := context.WithTimeout(ctx, bundleCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	prepareBundleCommand(cmd)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitedBuffer{b: &out, max: maxBundleFile}, &limitedBuffer{b: &out, max: maxBundleFile}
	err = cmd.Run()
	text := "$ " + exe + " " + strings.Join(args, " ") + "\n" + out.String()
	if err != nil {
		text += "\n(hata: " + err.Error() + ")\n"
	}
	return scrubLines(text)
}

type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// documentSummary lists the document without keys or addresses.
func documentSummary(doc *trust.Document) string {
	if doc == nil {
		return "Ağ belgesi yok.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Ağ: %s\nSürüm: %d (kök dönemi %d)\nVeriliş: %s\nGeçerlilik sonu: %s\nDNS alanı: %s\n",
		doc.DisplayName, doc.Version, doc.RootEpoch, doc.IssuedAt.UTC().Format(time.RFC3339), doc.ExpiresAt.UTC().Format(time.RFC3339), doc.DNSDomain)
	fmt.Fprintf(&b, "\nCihazlar (%d):\n", len(doc.Devices))
	for _, d := range doc.Devices {
		fmt.Fprintf(&b, "  - %s", d.Name)
		if len(d.Roles) > 0 {
			fmt.Fprintf(&b, " roller=%v", d.Roles)
		}
		if len(d.Tags) > 0 {
			fmt.Fprintf(&b, " etiketler=%v", d.Tags)
		}
		if !d.ExpiresAt.IsZero() {
			fmt.Fprintf(&b, " bitiş=%s", d.ExpiresAt.UTC().Format(time.RFC3339))
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "\nİptal edilenler: %d\n", len(doc.Revoked))
	fmt.Fprintf(&b, "\nKurallar (%d):\n", len(doc.Rules))
	for i, r := range doc.Rules {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, admin.RuleString(r))
	}
	if len(doc.Groups) > 0 {
		fmt.Fprintf(&b, "\nGruplar (%d):\n", len(doc.Groups))
		for _, g := range doc.Groups {
			fmt.Fprintf(&b, "  - %s: %v\n", g.Name, g.Members)
		}
	}
	return scrubLines(b.String())
}

// Bundle implements panel.Observability.
func (o *Observer) Bundle(ctx context.Context) (panel.BundleReply, error) {
	now := o.cfg.Now()
	b := &bundleBuilder{}
	b.add("README.txt", fmt.Sprintf(`OpenScale teşhis paketi
Oluşturma: %s

Bu paket yalnızca bu bilgisayarda oluşturuldu ve hiçbir yere gönderilmedi.
Paylaşmadan önce içeriğe bakın. IP adresleri kısaltıldı (ör. 203.0.*.*),
anahtara benzeyen değerler ve gizli ayarlar [REDACTED] ile değiştirildi.
Ağ belgesinden yalnızca cihaz adları, roller, etiketler ve kurallar alındı;
anahtarlar alınmadı.
`, now.UTC().Format(time.RFC3339)))
	b.add("version.txt", fmt.Sprintf("openscale %s\n%s/%s\n%s\n", version.Version, runtime.GOOS, runtime.GOARCH, runtime.Version()))
	b.addJSON("system.json", sysinfo.Collect(now))

	diag := &EngineDiag{Engine: o.cfg.Engine, Interface: o.cfg.Interface, Now: o.cfg.Now}
	if st, err := diag.BaseStatus(); err == nil {
		b.addJSON("status.json", st)
	} else {
		b.add("status.json", Scrub(err.Error())+"\n")
	}
	if o.cfg.Status != nil {
		b.addJSON("health.json", HealthOf(o.cfg.Status()))
	}
	if e := o.cfg.Engine(); e != nil {
		b.add("document.txt", documentSummary(e.Document()))
		b.addJSON("denied.json", deniedReply(e.PacketFilter()))
		if w, err := diag.DiagWireGuard(); err == nil {
			b.addJSON("wireguard.json", w)
		}
		if p, err := diag.DiagPaths(); err == nil {
			b.addJSON("paths.json", p)
		}
	} else {
		b.add("document.txt", "Tünel kapalı.\n")
	}
	evs, _ := o.bus.Since(ctx, 0, 0)
	b.addJSON("events.json", evs)
	if rep, err := o.AuditVerify(); err == nil {
		b.addJSON("audit-verify.json", rep)
	}
	var mb bytes.Buffer
	if err := o.writeMetrics(&mb); err == nil {
		b.add("metrics.txt", mb.String())
	}
	var gb bytes.Buffer
	if p := pprof.Lookup("goroutine"); p != nil && p.WriteTo(&gb, 1) == nil {
		b.add("goroutines.txt", scrubLines(gb.String()))
	}
	for name, text := range systemDumps(ctx) {
		b.add("system/"+name, text)
	}
	if o.cfg.BundleExtra != nil {
		for _, f := range o.cfg.BundleExtra(ctx) {
			b.add(f.Name, f.Content)
		}
	}
	o.Security("diagnostics_bundle", audit.SeverityInfo, panel.CategorySecurity, "",
		fmt.Sprintf("Teşhis paketi içeriği hazırlandı (%d dosya); dosya yalnızca sahibin onayıyla bu bilgisayara yazılır.", len(b.files)), false)
	return panel.BundleReply{Schema: panel.DiagSchema, CreatedAt: now, Files: b.files}, nil
}

// tailFile returns the end of a file, masked.
func tailFile(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := int64(0)
	if info.Size() > n {
		off = info.Size() - n
	}
	buf := make([]byte, info.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	s := string(buf)
	if off > 0 {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return scrubLines(s), nil
}
