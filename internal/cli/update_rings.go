package cli

import (
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"time"

	"github.com/openscale/openscale/internal/autoupdate"
	"github.com/openscale/openscale/internal/rollout"
)

// Update rings (#827, ADR-0235): "update rings status" on a device shows
// its ring and what the coordinator announced; on the coordinator host it
// shows the progress the coordinator keeps. "set" and "resume" are the
// owner's, on the coordinator host.

func init() {
	registerCommands(
		command{"update rings status", "Güncelleme halkaları: bu cihazın halkası (etiket ring-canary/ring-early, yoksa main), açık halka, bekleme süreleri, durdurma", cmdUpdateRingsStatus},
		command{"update rings set", "Halka bekleme süreleri (koordinatör sunucusunda): --canary 6h --early 24h", cmdUpdateRingsSet},
		command{"update rings resume", "Geri dönüş yüzünden durdurulan sürümü sürdürür (koordinatör sunucusunda)", cmdUpdateRingsResume},
	)
}

func cmdUpdateRingsStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "update rings status")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	type out struct {
		Coordinator *rollout.State        `json:"coordinator,omitempty"`
		Settings    *rollout.Settings     `json:"settings,omitempty"`
		Device      *autoupdate.RingsView `json:"device,omitempty"`
	}
	var o out
	if *stateDir != "" {
		if st, err := rollout.ReadState(*stateDir); err == nil {
			o.Coordinator = &st
			if s, err := rollout.ReadSettings(*stateDir); err == nil {
				o.Settings = &s
			}
		} else if !errors.Is(err, iofs.ErrNotExist) {
			fmt.Fprintf(env.Stderr, "uyarı: koordinatörün halka durumu okunamadı: %v\n", err)
		}
	}
	if v, err := autoupdate.ReadRingsView(autoupdate.DefaultPaths().Work); err == nil {
		o.Device = &v
	}
	if *asJSON {
		return printJSON(env.Stdout, o)
	}
	if o.Coordinator == nil && o.Device == nil {
		fmt.Fprintln(env.Stdout, "Halka bilgisi yok: bu cihaz koordinatörden henüz sürüm ilanı almadı ve burada koordinatör durumu yok.")
		fmt.Fprintln(env.Stdout, "Halkaya almak için cihaza etiket verin: ring-canary veya ring-early (etiketsiz cihazlar ring-main). Örnek: openscale device bulk --names <cihaz> --add-tags ring-canary (ya da panelde Cihazlar > Etiketler)")
		return nil
	}
	if o.Device != nil {
		printDeviceRings(env.Stdout, *o.Device)
	}
	if o.Coordinator != nil {
		if o.Device != nil {
			fmt.Fprintln(env.Stdout)
		}
		printCoordinatorRings(env.Stdout, *o.Coordinator, o.Settings)
	}
	return nil
}

func ringLabel(r string) string {
	switch r {
	case rollout.RingCanary:
		return "canary"
	case rollout.RingEarly:
		return "early"
	case rollout.RingMain:
		return "main"
	}
	return "-"
}

func hours(d time.Duration) string { return fmt.Sprintf("%g sa", d.Hours()) }

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("02.01.2006 15:04")
}

func printDeviceRings(w io.Writer, v autoupdate.RingsView) {
	fmt.Fprintf(w, "Bu cihazın halkası: %s\n", ringLabel(v.Ring))
	if v.Latest != "" {
		fmt.Fprintf(w, "Koordinatördeki sürüm: %s\n", v.Latest)
	}
	fmt.Fprintf(w, "Durum: %s\n", v.Message)
	ro := v.Rollout
	if ro == nil {
		return
	}
	if !ro.Announced {
		fmt.Fprintln(w, "Koordinatör halka ilerlemesi göndermiyor (eski sürüm); cihaz yalnızca kendi bekleme süresini uygular.")
	} else {
		fmt.Fprintf(w, "Açık halka: %s (koordinatöre göre)\n", ringLabel(ro.Open))
		if ro.Halted {
			fmt.Fprintf(w, "DURDURULDU: %s halkasında bir cihaz önceki sürüme döndü.\n", ringLabel(ro.HaltRing))
		}
	}
	fmt.Fprintf(w, "Bekleme süreleri: canary -> early %s, early -> main %s\n", hours(time.Duration(ro.CanarySoak)*time.Second), hours(time.Duration(ro.EarlySoak)*time.Second))
	fmt.Fprintf(w, "İlk görülme: %s", stamp(ro.FirstSeen))
	if !ro.NotBefore.IsZero() {
		fmt.Fprintf(w, ", bu cihazın kendi bekleme sınırı: %s", stamp(ro.NotBefore))
	}
	fmt.Fprintln(w)
	for _, c := range ro.Rings {
		fmt.Fprintf(w, "  %-7s %d cihaz, %d yeni sürümde, %d sağlıklı, %d geri döndü\n", ringLabel(c.Ring), c.Members, c.Updated, c.Healthy, c.RolledBack)
	}
}

func printCoordinatorRings(w io.Writer, st rollout.State, set *rollout.Settings) {
	fmt.Fprintf(w, "Koordinatör: %s yayımı, ilk ilan %s\n", st.Version, stamp(st.Since))
	if set != nil {
		fmt.Fprintf(w, "Bekleme süreleri: canary -> early %s, early -> main %s\n", hours(time.Duration(set.CanarySoak)), hours(time.Duration(set.EarlySoak)))
	}
	fmt.Fprintf(w, "early açıldı: %s, main açıldı: %s\n", stamp(st.EarlyAt), stamp(st.MainAt))
	if st.Halted {
		fmt.Fprintf(w, "DURDURULDU (%s): %s halkasında bir cihaz önceki sürüme döndü. İnceledikten sonra: openscale update rings resume\n", stamp(st.HaltedAt), ringLabel(st.HaltRing))
	}
	if a := st.Announcement; a != nil {
		for _, c := range a.Rings {
			fmt.Fprintf(w, "  %-7s %d cihaz, %d yeni sürümde, %d sağlıklı, %d geri döndü\n", ringLabel(c.Ring), c.Members, c.Updated, c.Healthy, c.RolledBack)
		}
	}
}

func cmdUpdateRingsSet(env *Env, args []string) error {
	fs := newFlagSet(env, "update rings set")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	canary := fs.Duration("canary", rollout.DefaultCanarySoak, "canary cihazların yeni sürümde sorunsuz çalışması gereken süre (early açılmadan önce)")
	early := fs.Duration("early", rollout.DefaultEarlySoak, "early cihazların yeni sürümde sorunsuz çalışması gereken süre (main açılmadan önce)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir gerekli")
	}
	set, err := rollout.ReadSettings(*stateDir)
	if err != nil {
		set = rollout.DefaultSettings()
	}
	set.CanarySoak, set.EarlySoak = rollout.Duration(*canary), rollout.Duration(*early)
	if err := set.Validate(); err != nil {
		return usageError("%v", err)
	}
	if err := autoupdate.WriteRingSettings(*stateDir, set); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Halka bekleme süreleri: canary -> early %s, early -> main %s. Koordinatör bir dakika içinde uygular.\n", hours(*canary), hours(*early))
	fmt.Fprintf(env.Stdout, "Cihazlar koordinatörün süresini en az %s olarak kabul eder; kendi saatlerine göre de bekler.\n", hours(rollout.MinSoak))
	return nil
}

func cmdUpdateRingsResume(env *Env, args []string) error {
	fs := newFlagSet(env, "update rings resume")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := rollout.ReadState(*stateDir)
	if err != nil {
		return fmt.Errorf("koordinatörün halka durumu okunamadı: %w", err)
	}
	if !st.Halted {
		fmt.Fprintf(env.Stdout, "%s durdurulmuş değil.\n", st.Version)
		return nil
	}
	set, err := rollout.ReadSettings(*stateDir)
	if err != nil {
		set = rollout.DefaultSettings()
	}
	set.ResumeDigest, set.ResumedAt = st.Digest, env.Now().UTC()
	if err := autoupdate.WriteRingSettings(*stateDir, set); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s sürdürülüyor; koordinatör bir dakika içinde uygular. Yeni bir geri dönüş sürümü yeniden durdurur.\n", st.Version)
	return nil
}
