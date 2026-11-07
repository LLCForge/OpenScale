package cli

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// Several coordinators and coordinator key rotation (ADR-0111; #153, #152).

func p15Commands() []command {
	return []command{
		{"network coordinator add", "Ek koordinatör ekler (VPS + ev sunucusu; cihazlar hepsine bağlanır)", cmdCoordinatorAdd},
		{"network coordinator remove", "Ek koordinatörü belgeden çıkarır", cmdCoordinatorRemove},
		{"network coordinator promote", "Ek koordinatörü birincil yapar; eskisi geçiş süresince ek kalır", cmdCoordinatorPromote},
		{"network coordinator rotate", "Koordinatör anahtarını yeniler; geçiş süresince eski ve yeni anahtar birlikte geçerli", cmdCoordinatorRotate},
		{"network coordinator prune", "Geçiş süresi bitmiş ek koordinatörleri belgeden çıkarır", cmdCoordinatorPrune},
		{"network coordinator list", "Belgedeki koordinatörleri listeler", cmdCoordinatorList},
	}
}

// coordinatorKey parses and checks --wireguard-key and --fingerprint.
func coordinatorKey(keyText, fingerprint string, needFingerprint bool) (trust.Key, error) {
	key, err := trust.ParseKey(strings.TrimSpace(keyText))
	if err != nil {
		return trust.Key{}, usageError("--wireguard-key geçerli bir WireGuard anahtarı değil")
	}
	if !needFingerprint {
		return key, nil
	}
	if fingerprint == "" {
		return trust.Key{}, usageError("--fingerprint zorunlu ('coordinator keygen' çıktısındaki parmak izi)")
	}
	got := []byte(trust.NormalizeFingerprint(fingerprint))
	want := []byte(trust.NormalizeFingerprint(trust.CoordinatorFingerprint(key)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return trust.Key{}, admin.ErrFingerprintMismatch
	}
	return key, nil
}

func cmdCoordinatorAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "network coordinator add")
	common := addEditFlags(fs)
	endpoint := fs.String("endpoint", "", "ek koordinatörün dış adresi, ör. ev.ornek.net:41820 (zorunlu)")
	keyText := fs.String("wireguard-key", "", "'coordinator keygen' çıktısındaki WireGuard açık anahtarı (zorunlu)")
	fingerprint := fs.String("fingerprint", "", "'coordinator keygen' çıktısındaki parmak izi (zorunlu)")
	name := fs.String("name", "", "kısa ad, ör. ev (isteğe bağlı)")
	region := fs.String("region", "", "bölge etiketi, ör. ist (isteğe bağlı; seçim gecikmeye göre yapılır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *endpoint == "" || *keyText == "" {
		return usageError("--endpoint, --wireguard-key ve --fingerprint zorunlu")
	}
	key, err := coordinatorKey(*keyText, *fingerprint, true)
	if err != nil {
		return err
	}
	ep := strings.TrimSpace(*endpoint)
	if err := runEdit(env, common, func(doc *trust.Document) error { return doc.AddCoordinator(ep, key, *name, *region) }); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Not: belge artık 'coordinators' alanını içeriyor; bu alanı bilmeyen eski cihazlar ve koordinatörler belgeyi reddeder. Önce hepsini güncelle (ADR-0111).")
	return nil
}

func cmdCoordinatorRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "network coordinator remove")
	common := addEditFlags(fs)
	keyText := fs.String("wireguard-key", "", "çıkarılacak ek koordinatörün WireGuard anahtarı (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	key, err := coordinatorKey(*keyText, "", false)
	if err != nil {
		return err
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.RemoveCoordinator(key) })
}

func cmdCoordinatorPromote(env *Env, args []string) error {
	fs := newFlagSet(env, "network coordinator promote")
	common := addEditFlags(fs)
	keyText := fs.String("wireguard-key", "", "birincil yapılacak ek koordinatörün WireGuard anahtarı (zorunlu)")
	transition := fs.Duration("transition", 0, "eski birincil bu süre sonra kullanılmaz (ör. 720h); 0: süresiz ek koordinatör kalır")
	preflight := fs.String("preflight", "", "yeni koordinatörde 'coordinator preflight --save' ile alınan sonuç; ulaşamayan cihaz varsa imzalanmaz (#485)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	key, err := coordinatorKey(*keyText, "", false)
	if err != nil {
		return err
	}
	if err := checkPromotePreflight(env, *preflight, key.String()); err != nil {
		return err
	}
	if *transition < 0 || *transition > trust.MaxCoordinatorTransition {
		return usageError("--transition 0 ile %d gün arasında olmalı", int(trust.MaxCoordinatorTransition.Hours()/24))
	}
	var until time.Time
	if *transition > 0 {
		until = env.Now().Add(*transition)
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.PromoteCoordinator(key, until) })
}

func cmdCoordinatorRotate(env *Env, args []string) error {
	fs := newFlagSet(env, "network coordinator rotate")
	common := addEditFlags(fs)
	endpoint := fs.String("endpoint", "", "yeni anahtarla çalışan koordinatörün dış adresi (eskisinden farklı port; zorunlu)")
	keyText := fs.String("wireguard-key", "", "yeni koordinatör anahtarı (zorunlu)")
	fingerprint := fs.String("fingerprint", "", "yeni anahtarın parmak izi (zorunlu)")
	name := fs.String("name", "", "kısa ad (isteğe bağlı)")
	region := fs.String("region", "", "bölge etiketi (isteğe bağlı)")
	transition := fs.Duration("transition", trust.DefaultCoordinatorTransition, "eski anahtarın geçerli kalacağı süre (1h-400 gün)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *endpoint == "" || *keyText == "" {
		return usageError("--endpoint, --wireguard-key ve --fingerprint zorunlu")
	}
	key, err := coordinatorKey(*keyText, *fingerprint, true)
	if err != nil {
		return err
	}
	ep := strings.TrimSpace(*endpoint)
	now := env.Now()
	if err := runEdit(env, common, func(doc *trust.Document) error {
		return doc.RotateCoordinator(ep, key, *name, *region, *transition, now)
	}); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Eski anahtar %s tarihine kadar ek koordinatör olarak geçerli; o zamana kadar eski koordinatör sürecini çalıştırmaya devam et, sonra 'network coordinator prune'.\n", now.Add(*transition).UTC().Format(time.RFC3339))
	return nil
}

func cmdCoordinatorPrune(env *Env, args []string) error {
	fs := newFlagSet(env, "network coordinator prune")
	common := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	now := env.Now()
	return runEdit(env, common, func(doc *trust.Document) error {
		if doc.PruneCoordinators(now) == 0 {
			return fmt.Errorf("geçiş süresi bitmiş ek koordinatör yok")
		}
		return doc.Validate()
	})
}

func cmdCoordinatorList(env *Env, args []string) error {
	doc, err := loadDocument(env, args, "network coordinator list")
	if err != nil || doc == nil {
		return err
	}
	all := doc.AllCoordinators()
	if len(all) == 0 {
		fmt.Fprintln(env.Stdout, "Belgede koordinatör yok.")
		return nil
	}
	now := env.Now()
	for i, c := range all {
		role := "ek"
		if i == 0 {
			role = "birincil"
		}
		state := ""
		switch {
		case c.Expired(now):
			state = " (geçiş bitti; kullanılmıyor)"
		case !c.Until.IsZero():
			state = " (geçiş sonu " + c.Until.UTC().Format(time.RFC3339) + ")"
		}
		fmt.Fprintf(env.Stdout, "%-9s %-12s %-24s %s  %s  bölge=%s%s\n", role, c.Name, c.Endpoint, c.IPv4, trust.CoordinatorFingerprint(c.WireGuardKey), p15Dash(c.Region), state)
	}
	return nil
}

func p15Dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
