package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/flightrec"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/troubleshoot"
)

// Phase 2 diagnostics commands: the flight recorder (#836) and the layered
// troubleshooter (#835). Both need the OpenScale service.

func init() { registerCommands(p2DiagCommands()...) } // g4_registry.go

func p2DiagCommands() []command {
	return []command{
		{"debug freeze", "Uçuş kaydediciyi (son 30 dk ayrıntılı, maskeli günlük) dondurur; --to ile yardımcının anahtarına şifreli dosya yazar", cmdDebugFreeze},
		{"debug freezes", "Saklanan uçuş kayıtlarını ve kaydedicinin doluluğunu gösterir (--json)", cmdDebugFreezes},
		{"troubleshoot", "Bağlantı sorununu katman katman arar: arayüz, ağ geçidi, DNS, koordinatör, aktarıcı, eşler (--json)", cmdTroubleshoot},
	}
}

// maxFlightExport bounds a sealed recording read from the service.
const maxFlightExport = bundlecrypt.MaxPlaintext + 1<<10

func cmdDebugFreeze(env *Env, args []string) error {
	fs := newFlagSet(env, "debug freeze")
	df := addDiagFlags(fs)
	toText := fs.String("to", "", "yardımcının 'osbk1:' ile başlayan açık anahtarı; verilirse şifreli dosya yazılır")
	id := fs.String("id", "", "saklanan bir kaydı dışa ver ('openscale debug freezes' kimliği; --to ile)")
	out := fs.String("o", "", "yazılacak dosya (varsayılan: openscale-ucus-<zaman>.osb)")
	force := fs.Bool("force", false, "var olan dosyanın üzerine yaz")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *id != "" && !flightrec.ValidID(*id) {
		return usageError("--id geçersiz; kimlikleri 'openscale debug freezes' gösterir")
	}
	to, err := bundleRecipient(*toText)
	if err != nil {
		return err
	}
	if to == nil && (*id != "" || *out != "") {
		return usageError("--id ve -o yalnızca --to ile kullanılır")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	if to == nil {
		var rep panel.FlightRecFreezeReply
		if err := c.post(env, "/flightrec/freeze", nil, &rep); err != nil {
			return err
		}
		if *df.json {
			return printJSON(env.Stdout, rep)
		}
		fmt.Fprintf(env.Stdout, "Uçuş kaydı donduruldu ve bu bilgisayarda şifreli saklandı: %s\n", rep.Saved.ID)
		fmt.Fprintln(env.Stdout, "Yardım edecek kişiye vermek için: openscale debug freeze --id", rep.Saved.ID, "--to <açık anahtar>")
		return nil
	}
	sealed, err := c.raw(env, "/flightrec/export", panel.FlightRecExportRequest{ID: *id, To: *toText})
	if err != nil {
		return err
	}
	name := *out
	if name == "" {
		name = "openscale-ucus-" + env.Now().Format("20060102-150405") + ".osb"
	}
	f, err := createOutput(name, *force)
	if err != nil {
		return err
	}
	if _, err := f.Write(sealed); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, map[string]any{"schema": panel.DiagSchema, "file": name, "fingerprint": bundlecrypt.Fingerprint(to), "size": len(sealed)})
	}
	fmt.Fprintf(env.Stdout, "%s yazıldı (şifreli; alıcı anahtar parmak izi %s).\n", name, bundlecrypt.Fingerprint(to))
	fmt.Fprintln(env.Stdout, "Yalnızca o anahtarın sahibi 'openscale debug bundle-open' ile açabilir; anahtarlar, IP'ler ve cihaz adları kayıtta maskelidir.")
	return nil
}

// raw posts body and returns the response bytes (a sealed file), bounded.
func (c *localClient) raw(env *Env, path string, body any) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(envContext(env), http.MethodPost, c.base+panel.LocalAPIPrefix+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tünelin yerel API'sine ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxFlightExport+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(reply, &e) == nil && e.Error != "" {
			return nil, &apiError{status: resp.StatusCode, msg: e.Error}
		}
		return nil, &apiError{status: resp.StatusCode, msg: "yerel API yanıtı: " + resp.Status}
	}
	if len(reply) > maxFlightExport || !bundlecrypt.IsSealed(reply) {
		return nil, errors.New("servis beklenmeyen bir yanıt verdi")
	}
	return reply, nil
}

func cmdDebugFreezes(env *Env, args []string) error {
	fs := newFlagSet(env, "debug freezes")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.FlightRecStatus
	if err := c.get(env, "/flightrec", &st); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	w := env.Stdout
	if !st.Enabled {
		fmt.Fprintln(w, "Uçuş kaydedici çalışmıyor:", st.Error)
		return nil
	}
	fmt.Fprintf(w, "Kaydedici: %d kayıt, %s / %s, en fazla %d dk geriye.\n", st.Stats.Entries, humanBytes(uint64(st.Stats.Bytes)), humanBytes(uint64(st.Stats.MaxBytes)), st.Stats.MaxAgeS/60)
	if st.AutoFreeze {
		fmt.Fprintf(w, "Kopma algılanınca kendiliğinden dondurulur (en çok %d dakikada bir).\n", st.AutoEvery/60)
	}
	if st.Error != "" {
		fmt.Fprintln(w, "Uyarı:", st.Error)
	}
	if len(st.Stored) == 0 {
		fmt.Fprintln(w, "Saklanan kayıt yok.")
		return nil
	}
	fmt.Fprintln(w, "\nSaklanan kayıtlar:")
	for _, s := range st.Stored {
		fmt.Fprintf(w, "  %s  %s  %-18s %s\n", s.ID, s.At.Local().Format("2006-01-02 15:04:05"), freezeReasonText(s.Reason), humanBytes(uint64(max(s.Size, 0))))
	}
	return nil
}

func freezeReasonText(r string) string {
	switch r {
	case flightrec.ReasonManual:
		return "elle"
	case flightrec.ReasonTunnelDown:
		return "tünel düştü"
	case flightrec.ReasonCoordinatorLost:
		return "koordinatör koptu"
	}
	return r
}

func cmdTroubleshoot(env *Env, args []string) error {
	fs := newFlagSet(env, "troubleshoot")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	// The run may take longer than one ordinary call.
	c.http.Timeout = 75 * time.Second
	var rep troubleshoot.Report
	if err := c.post(env, "/troubleshoot", nil, &rep); err != nil {
		return err
	}
	if *df.json {
		if err := printJSON(env.Stdout, rep); err != nil {
			return err
		}
	} else {
		printTroubleshoot(env.Stdout, rep)
	}
	if !rep.OK {
		return exitCodeError{code: exitError}
	}
	return nil
}

func printTroubleshoot(w io.Writer, rep troubleshoot.Report) {
	marks := map[troubleshoot.Status]string{troubleshoot.Pass: "geçti  ", troubleshoot.Fail: "KALDI  ", troubleshoot.Warn: "uyarı  ", troubleshoot.Skip: "atlandı"}
	for _, s := range rep.Steps {
		fmt.Fprintf(w, "[%s] %s", marks[s.Status], s.Title)
		if s.Code != "" && s.Status != troubleshoot.Pass {
			fmt.Fprintf(w, " (%s)", s.Code)
		}
		fmt.Fprintln(w)
		if s.Detail != "" {
			fmt.Fprintf(w, "          %s\n", s.Detail)
		}
		if s.Fix != "" && (s.Status == troubleshoot.Fail || s.Status == troubleshoot.Warn) {
			fmt.Fprintf(w, "          Öneri: %s\n", s.Fix)
		}
	}
	fmt.Fprintln(w)
	if rep.OK {
		fmt.Fprintln(w, "Sorun bulunmadı.")
		return
	}
	first := rep.Steps[rep.FirstFailure]
	line := "İlk sorun: " + first.Title
	if first.Code != "" {
		line += " — ayrıntı: openscale explain " + first.Code
	}
	fmt.Fprintln(w, strings.TrimSpace(line))
}
