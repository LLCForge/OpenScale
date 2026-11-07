package cli

import (
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/openscale/openscale/internal/panel"
)

// Edge device modes and hardening (P11, ADR-0154): the device travel
// profile, game and metered modes, the lock shield, the integrity gate,
// local network attack detection, the hardening audit and the service's
// attack surface. Every command talks to the running service with the
// app token, so it needs an administrator.

func p11EdgeCommands() []command {
	return []command{
		{"edge mode", "Uç cihaz kipi: travel (seyahat profili), game (oyun), metered (ölçülü bağlantı) veya off; kapatınca önceki ayarlar döner", cmdEdgeMode},
		{"edge options", "Uç cihaz seçenekleri: kilitte kalkan, açılışta bütünlük şartı, yerel ağ saldırısı tespiti, otomatik ölçülü kip", cmdEdgeOptions},
		{"edge audit", "Sertleştirme denetimi: program bütünlüğü, kripto öz sınaması, kill switch'i delebilecek üçüncü taraf WFP filtreleri", cmdEdgeAudit},
		{"edge status", "Açık kipi, değiştirdiği ayarları, seçenekleri ve yerel ağ uyarılarını gösterir", cmdEdgeStatus},
		{"edge", "Uç cihaz durumu (edge status ile aynı)", cmdEdgeStatus},
		{"surface", "Saldırı yüzeyi: OpenScale servisinin açtığı her port ve soket, amacı, erişimi ve kuralı", cmdSurface},
	}
}

func cmdEdgeStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "edge status")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.EdgeStatus
	if err := c.get(env, "/edge", &st); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	printEdgeStatus(env.Stdout, st)
	return nil
}

func printEdgeStatus(w io.Writer, st panel.EdgeStatus) {
	if st.Mode == "" {
		fmt.Fprintln(w, "Kip: yok")
	} else {
		line := "Kip: " + st.Mode
		if st.ModeSince != nil {
			line += ", " + st.ModeSince.Local().Format("02.01.2006 15:04") + " itibarıyla"
		}
		if st.ModeAuto != "" {
			line += " (otomatik: " + st.ModeAuto + ")"
		}
		fmt.Fprintln(w, line)
		for _, ch := range st.Changes {
			fmt.Fprintf(w, "  %s: %s -> %s\n", ch.Key, orDash(ch.From), ch.To)
		}
	}
	o := st.Options
	fmt.Fprintf(w, "Ekran kilitlenince kalkan: %s", onOff(o.LockShield))
	if st.LockShield {
		fmt.Fprint(w, " (şu an kilit nedeniyle açık)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Açılışta bütünlük şartı: %s\n", onOff(o.RequireIntegrity))
	fmt.Fprintf(w, "Yerel ağ saldırısı tespiti: %s", onOff(!o.LANGuardOff))
	if o.LANGuardTravel {
		fmt.Fprintf(w, ", şüphede seyahat profili (%s)", o.TravelExit)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Otomatik ölçülü kip: %s", onOff(o.AutoMetered))
	switch {
	case st.Metered == nil:
		fmt.Fprint(w, " (sistem ölçülü bağlantı bilgisi vermiyor)")
	case *st.Metered:
		fmt.Fprint(w, " (bağlantı şu an ölçülü)")
	default:
		fmt.Fprint(w, " (bağlantı ölçülü değil)")
	}
	fmt.Fprintln(w)
	if len(st.LANAlerts) > 0 {
		fmt.Fprintln(w, "\nYerel ağ uyarıları:")
		for _, a := range st.LANAlerts {
			fmt.Fprintf(w, "  %s  %s\n", a.At.Local().Format("02.01 15:04"), a.Message)
		}
	}
	for _, n := range st.Notes {
		fmt.Fprintln(w, "Not: "+n)
	}
}

func cmdEdgeMode(env *Env, args []string) error {
	fs := newFlagSet(env, "edge mode")
	df := addDiagFlags(fs)
	exit := fs.String("exit", "", "seyahat profilinde kullanılacak çıkış düğümü")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("kip adı gerekli: travel, game, metered veya off")
	}
	mode := strings.ToLower(pos[0])
	switch mode {
	case panel.EdgeModeTravel, panel.EdgeModeGame, panel.EdgeModeMetered, panel.EdgeModeOff:
	default:
		return usageError("bilinmeyen kip %q; travel, game, metered veya off", pos[0])
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.EdgeStatus
	if err := c.post(env, "/edge/mode", panel.EdgeModeRequest{Mode: mode, ExitNode: *exit}, &st); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	printEdgeStatus(env.Stdout, st)
	return nil
}

func cmdEdgeOptions(env *Env, args []string) error {
	fs := newFlagSet(env, "edge options")
	df := addDiagFlags(fs)
	lock := fs.Bool("lock-shield", false, "ekran kilitlenince gelen bağlantıları reddet, kilit açılınca eski hâline dön")
	integrity := fs.Bool("require-integrity", false, "program imzalı manifestoyla eşleşmezse tüneli açma")
	guard := fs.Bool("lan-guard", true, "ağ geçidinin donanım adresi değişince uyar (ARP sahteciliği)")
	guardTravel := fs.Bool("lan-guard-travel", false, "saldırı şüphesinde seyahat profilini kendiliğinden aç (--travel-exit gerekir)")
	metered := fs.Bool("auto-metered", false, "sistem bağlantıyı ölçülü bildirince ölçülü kipi aç, bitince kapat")
	travelExit := fs.String("travel-exit", "", "otomatik seyahat profilinin çıkış düğümü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var ch panel.EdgeOptionsChange
	set := 0
	fs.Visit(func(f *flag.Flag) {
		set++
		switch f.Name {
		case "lock-shield":
			ch.LockShield = lock
		case "require-integrity":
			ch.RequireIntegrity = integrity
		case "lan-guard":
			ch.LANGuard = guard
		case "lan-guard-travel":
			ch.LANGuardTravel = guardTravel
		case "auto-metered":
			ch.AutoMetered = metered
		case "travel-exit":
			ch.TravelExit = travelExit
		default:
			set--
		}
	})
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.EdgeStatus
	if set == 0 {
		err = c.get(env, "/edge", &st)
	} else {
		err = c.post(env, "/edge/options", ch, &st)
	}
	if err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	printEdgeStatus(env.Stdout, st)
	return nil
}

func cmdEdgeAudit(env *Env, args []string) error {
	fs := newFlagSet(env, "edge audit")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.EdgeAuditReply
	if err := c.get(env, "/edge/audit", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	for _, k := range rep.Checks {
		fmt.Fprintf(env.Stdout, "[%s] %s: %s\n", strings.ToUpper(k.Level), k.Area, k.Message)
	}
	return nil
}

func cmdSurface(env *Env, args []string) error {
	fs := newFlagSet(env, "surface")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.SurfaceReply
	if err := c.get(env, "/edge/surface", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	if len(rep.Entries) == 0 {
		fmt.Fprintln(env.Stdout, "OpenScale servisinin açık soketi yok.")
	} else {
		tw := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PROTO\tADRES\tAMAÇ\tERİŞİM\tKURAL")
		for _, e := range rep.Entries {
			addr := e.Address + ":" + strconv.Itoa(int(e.Port))
			if strings.Contains(e.Address, ":") {
				addr = "[" + e.Address + "]:" + strconv.Itoa(int(e.Port))
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Proto, addr, e.Purpose, e.Reach, e.Rule)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	for _, n := range rep.Notes {
		fmt.Fprintln(env.Stdout, "\n"+n)
	}
	return nil
}
