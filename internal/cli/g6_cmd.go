package cli

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/tpm"
)

// G6 commands (ADR-0204..0208): extended posture, screen share check,
// secure delete, tamper log verification, metadata preview and TPM
// evidence. End-to-end sending needs the running node's device key and is
// started from the panel (POST /api/app/e2e/send).

func init() {
	registerCommands(
		command{"posture-ext", "Önyükleme ve ekran kilidi duruşu: Secure Boot, TPM, ekran kilidi, genel not [--require secure-boot,tpm,screen-lock] [--json]", cmdPostureExt},
		command{"screen-share", "Ekran paylaşan veya kaydeden masaüstü uygulamalarını gösterir (Teams, Zoom, OBS...; yalnızca süreç adları) [--json]", cmdScreenShare},
		command{"secure-delete", "Dosyayı veya klasörü üzerine yazarak siler: <yol> --yes (SSD sınırı için ADR-0206)", cmdSecureDelete},
		command{"tamper verify", "Kurcalama günlüğünün imzalarını ve zincirini doğrular: <günlük> --key <cihaz imza anahtarı, base64>", cmdTamperVerify},
		command{"e2e strip", "Gönderimde yapılacak üst veri temizliğini önizler: <dosya> <çıktı> (EXIF, XMP, Office yazarı, PDF üreticisi)", cmdE2EStrip},
		command{"tpm evidence", "Katılımda sunulacak TPM kanıtını gösterir (yalnızca okuma: varlık, üretici, EK sertifikası) [--json]", cmdTPMEvidence},
	)
}

type postureExtJSON struct {
	Schema      int      `json:"schema"`
	SecureBoot  string   `json:"secure_boot"`
	TPM         string   `json:"tpm"`
	ScreenLock  string   `json:"screen_lock"`
	LockMinutes int      `json:"lock_minutes"`
	Disk        string   `json:"disk_encryption"`
	Grade       string   `json:"grade"`
	Reasons     []string `json:"reasons"`
	Unmet       []string `json:"unmet"`
	Note        string   `json:"note"`
}

func parseBootRequirement(s string) (posture.BootRequirement, error) {
	var q posture.BootRequirement
	for part := range strings.SplitSeq(s, ",") {
		switch strings.TrimSpace(part) {
		case "":
		case "secure-boot":
			q.SecureBoot = true
		case "tpm":
			q.TPM = true
		case "screen-lock":
			q.ScreenLock = true
		default:
			return q, usageError("bilinmeyen koşul %q (secure-boot, tpm, screen-lock)", part)
		}
	}
	return q, nil
}

func cmdPostureExt(env *Env, args []string) error {
	fs := newFlagSet(env, "posture-ext")
	require := fs.String("require", "", "karşılanması istenen koşullar: secure-boot,tpm,screen-lock (karşılanmazsa hata döner)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	q, err := parseBootRequirement(*require)
	if err != nil {
		return err
	}
	r := posture.Collect()
	x := posture.CollectExtended()
	r = x.Merge(r)
	grade, why := posture.Classify(r, x)
	unmet := posture.EvaluateExtended(q, x)
	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(postureExtJSON{Schema: 1, SecureBoot: stateCode(x.SecureBoot), TPM: stateCode(x.TPM),
			ScreenLock: stateCode(x.ScreenLock), LockMinutes: x.LockMinutes, Disk: stateCode(r.DiskEncryption),
			Grade: string(grade), Reasons: nonNil(why), Unmet: nonNil(unmet), Note: posture.Disclaimer}); err != nil {
			return err
		}
	} else {
		w := env.Stdout
		fmt.Fprintf(w, "Secure Boot:      %s\n", x.SecureBoot)
		fmt.Fprintf(w, "TPM 2.0:          %s\n", x.TPM)
		fmt.Fprintf(w, "Disk şifreleme:   %s\n", r.DiskEncryption)
		lock := x.ScreenLock.String()
		if x.LockMinutes > 0 {
			lock += fmt.Sprintf(" (%d dakika)", x.LockMinutes)
		}
		fmt.Fprintf(w, "Ekran kilidi:     %s\n", lock)
		fmt.Fprintf(w, "Genel durum:      %s\n", gradeText(grade))
		for _, s := range why {
			fmt.Fprintf(w, "Zayıflık: %s\n", s)
		}
		if x.ScreenLock == posture.Unknown {
			fmt.Fprintln(w, "Not: ekran kilidi kullanıcı oturumunda okunur; servis olarak çalışırken \"bilinmiyor\" olabilir.")
		}
		fmt.Fprintln(w, posture.Disclaimer)
		for _, u := range unmet {
			fmt.Fprintf(w, "Karşılanmayan koşul: %s\n", u)
		}
	}
	if len(unmet) > 0 {
		return fmt.Errorf("%d koşul karşılanmadı", len(unmet))
	}
	return nil
}

func gradeText(g posture.Grade) string {
	switch g {
	case posture.GradeStrong:
		return "güçlü"
	case posture.GradeWeak:
		return "zayıf"
	}
	return "bilinmiyor"
}

func cmdScreenShare(env *Env, args []string) error {
	fs := newFlagSet(env, "screen-share")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st := privacy.DetectScreenShare(env.Now())
	if *asJSON {
		return json.NewEncoder(env.Stdout).Encode(st)
	}
	switch st.Level {
	case privacy.ShareActive:
		fmt.Fprintln(env.Stdout, "Ekran şu anda paylaşılıyor veya kaydediliyor olabilir.")
	case privacy.SharePossible:
		fmt.Fprintln(env.Stdout, "Ekranı paylaşabilecek bir uygulama açık.")
	default:
		fmt.Fprintln(env.Stdout, "Ekranı paylaşan bilinen bir masaüstü uygulaması görülmedi.")
	}
	for _, a := range st.Apps {
		fmt.Fprintf(env.Stdout, "  %s\n", a)
	}
	fmt.Fprintln(env.Stdout, st.BrowserNote)
	return nil
}

func cmdSecureDelete(env *Env, args []string) error {
	fs := newFlagSet(env, "secure-delete")
	yes := fs.Bool("yes", false, "onay: silinen veri geri getirilemez")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if !*yes {
		return usageError("geri dönüşü yok; onaylamak için --yes ekleyin")
	}
	res, err := privacy.SecureRemove(fs.Arg(0))
	if err != nil {
		if errors.Is(err, privacy.ErrUnsafePath) {
			return errors.New("bu konum güvenli silme için kabul edilmiyor (sistem, ev veya kök klasörü)")
		}
		return err
	}
	fmt.Fprintf(env.Stdout, "%d dosya silindi, %d tanesinin içeriği üzerine yazıldı (%s).\n", res.Files, res.Overwritten, formatBytes(res.Bytes))
	for _, n := range res.NotOverwritten {
		fmt.Fprintf(env.Stdout, "Yalnızca adı silindi (bağlantı veya çok büyük): %s\n", n)
	}
	fmt.Fprintln(env.Stdout, "Not: SSD ve kopyala-yaz dosya sistemlerinde eski bloklar kalabilir; tam koruma disk şifrelemesidir.")
	return nil
}

func cmdTamperVerify(env *Env, args []string) error {
	fs := newFlagSet(env, "tamper verify")
	key := fs.String("key", "", "cihazın imza anahtarı (base64, imzalı belgedeki signing_key)")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(*key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return usageError("--key 32 baytlık base64 Ed25519 anahtarı olmalı")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	events, verr := posture.VerifyTamperLog(bufio.NewReader(f), ed25519.PublicKey(pub))
	for _, e := range events {
		fmt.Fprintf(env.Stdout, "%d  %s  %s  %s\n", e.Seq, e.At.Local().Format("2006-01-02 15:04:05"), tamperKind(e.Kind), e.Path)
	}
	if verr != nil {
		return fmt.Errorf("günlük doğrulanamadı: %w", verr)
	}
	fmt.Fprintf(env.Stdout, "%d olay doğrulandı; imzalar ve zincir sağlam.\n", len(events))
	return nil
}

func tamperKind(k string) string {
	switch k {
	case posture.TamperChanged:
		return "değişti"
	case posture.TamperRemoved:
		return "silindi"
	case posture.TamperAdded:
		return "eklendi"
	}
	return k
}

func cmdE2EStrip(env *Env, args []string) error {
	fs := newFlagSet(env, "e2e strip")
	if err := parseFlagsWithArgs(fs, args, 2); err != nil {
		return err
	}
	in, out := fs.Arg(0), fs.Arg(1)
	if filepath.Clean(in) == filepath.Clean(out) {
		return usageError("çıktı dosyası girdiden farklı olmalı")
	}
	st, err := os.Stat(in)
	if err != nil {
		return err
	}
	if st.Size() > 256<<20 {
		return errors.New("dosya önizleme için çok büyük (en çok 256 MiB)")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	clean, err := p2psend.StripForSend(in, data)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(clean)
	if err := errors.Join(werr, f.Close()); err != nil {
		return err
	}
	if len(clean) == len(data) && string(clean) == string(data) {
		fmt.Fprintln(env.Stdout, "Temizlenecek üst veri bulunmadı; dosya olduğu gibi kopyalandı.")
		return nil
	}
	fmt.Fprintf(env.Stdout, "Üst veri temizlendi: %s -> %s\n", formatBytes(int64(len(data))), formatBytes(int64(len(clean))))
	return nil
}

func cmdTPMEvidence(env *Env, args []string) error {
	fs := newFlagSet(env, "tpm evidence")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	p, err := tpm.Detect()
	if err != nil && !errors.Is(err, tpm.ErrNotFound) {
		return err
	}
	var t tpm.Transport
	if p.Present && p.Version == "2.0" {
		if tr, err := tpm.Open(); err == nil {
			defer tr.Close()
			t = tr
		}
	}
	e := tpm.CollectEvidence(p, t)
	if *asJSON {
		return json.NewEncoder(env.Stdout).Encode(e)
	}
	fmt.Fprintf(env.Stdout, "TPM: %v (sürüm %s, üretici %s)\n", e.TPM, orDash(e.Version), orDash(e.Manufacturer))
	fmt.Fprintf(env.Stdout, "Kanıt yöntemi: %s\n", e.Method)
	if len(e.EKCert) > 0 {
		v := tpm.EvaluateJoin(tpm.JoinPolicy{}, e, nil, env.Now())
		fmt.Fprintf(env.Stdout, "EK sertifikası parmak izi: %s\n", v.EKFingerprint)
	}
	fmt.Fprintln(env.Stdout, "Not: bu kanıt, anahtarın TPM içinde olduğunu tek başına kanıtlamaz (ADR-0208).")
	return nil
}
