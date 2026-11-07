package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// --- exit-dns: resolver guard controls on an exit node (P05) ---

func cmdExitDNS(env *Env, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return cmdExitDNSStatus(env, args[1:])
		case "allow":
			return cmdExitDNSAllow(env, args[1:])
		case "revoke":
			return cmdExitDNSRevoke(env, args[1:])
		case "log":
			return cmdExitDNSLog(env, args[1:])
		}
		if !strings.HasPrefix(args[0], "-") {
			return usageError("bilinmeyen alt komut %q; status, allow, revoke veya log", args[0])
		}
	}
	return cmdExitDNSStatus(env, args)
}

func cmdExitDNSStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-dns status")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.ExitDNSReply
	if err := c.get(env, "/exit-dns", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	w := env.Stdout
	s := rep.Stats
	fmt.Fprintf(w, "Yeniden bağlama engeli: %d, AAAA süzülen: %d, güvenli arama: %d\n", s.Rebind, s.AAAAFiltered, s.SafeSearch)
	fmt.Fprintf(w, "Hız sınırına takılan: %d, tünelleme işareti: %d\n", s.RateLimited, s.TunnelFlags)
	fmt.Fprintf(w, "Bayat yanıt: %d, ön getirme: %d, istisnayla geçen: %d\n", s.Stale, s.Prefetched, s.Exceptions)
	if rep.LogUntil != nil {
		fmt.Fprintf(w, "Sorgu günlüğü açık (yalnızca bellekte): %s saatine kadar\n", rep.LogUntil.Local().Format("15:04"))
	} else {
		fmt.Fprintln(w, "Sorgu günlüğü kapalı.")
	}
	if len(rep.Exceptions) == 0 {
		fmt.Fprintln(w, "Süreli istisna yok.")
		return nil
	}
	fmt.Fprintln(w, "\nSüreli istisnalar:")
	for _, e := range rep.Exceptions {
		fmt.Fprintf(w, "  %s  %s saatine kadar\n", strings.TrimSuffix(e.Name, "."), e.Until.Local().Format("15:04"))
	}
	return nil
}

func cmdExitDNSAllow(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-dns allow")
	df := addDiagFlags(fs)
	dur := fs.Duration("for", 15*time.Minute, "istisna süresi (1m-24h)")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if *dur < node.MinExitDNSException || *dur > node.MaxExitDNSException {
		return usageError("--for 1m ile 24h arasında olmalı")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var ex node.ExitDNSException
	body := map[string]any{"name": strings.TrimSpace(fs.Arg(0)), "seconds": int64(*dur / time.Second)}
	if err := c.post(env, "/exit-dns/allow", body, &ex); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, ex)
	}
	fmt.Fprintf(env.Stdout, "%s ve alt adları %s saatine kadar engel listesinden muaf; süre dolunca kendiliğinden kapanır.\n",
		strings.TrimSuffix(ex.Name, "."), ex.Until.Local().Format("15:04"))
	return nil
}

func cmdExitDNSRevoke(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-dns revoke")
	df := addDiagFlags(fs)
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(fs.Arg(0))
	if err := c.post(env, "/exit-dns/revoke", map[string]string{"name": name}, nil); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s için süreli istisna kapatıldı.\n", name)
	return nil
}

func cmdExitDNSLog(env *Env, args []string) error {
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	fs := newFlagSet(env, "exit-dns log")
	df := addDiagFlags(fs)
	dur := fs.Duration("for", time.Hour, "günlüğün açık kalacağı süre (en çok 1h)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.ExitDNSLogReply
	switch action {
	case "on":
		if *dur <= 0 || *dur > node.MaxExitDNSQueryLog {
			return usageError("--for 1s ile 1h arasında olmalı")
		}
		if err := c.post(env, "/exit-dns/log", map[string]int64{"seconds": int64(*dur / time.Second)}, &rep); err != nil {
			return err
		}
		if rep.Until != nil {
			fmt.Fprintf(env.Stdout, "Sorgu günlüğü %s saatine kadar açık; yalnızca bellekte tutulur, kapanınca silinir.\n", rep.Until.Local().Format("15:04"))
		}
		return nil
	case "off":
		if err := c.post(env, "/exit-dns/log", map[string]int64{"seconds": 0}, &rep); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Sorgu günlüğü kapatıldı ve silindi.")
		return nil
	case "show":
	default:
		return usageError("exit-dns log on|off|show")
	}
	if err := c.get(env, "/exit-dns/log", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	if rep.Until == nil {
		fmt.Fprintln(env.Stdout, "Sorgu günlüğü kapalı; açmak için: openscale exit-dns log on --for 30m")
		return nil
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ZAMAN\tCİHAZ\tAD\tTÜR\tKARAR")
	for _, e := range rep.Entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.At.Local().Format("15:04:05"), orDash(e.Device), strings.TrimSuffix(e.Name, "."), e.Type, e.Decision)
	}
	return tw.Flush()
}

// --- network dns profile: per-device filter profiles in the document ---

const dnsProfileOldDevicesNote = "Not: eski sürümlü cihazlar dns_profiles alanı olan belgeyi reddeder; önce bütün cihazları güncelle."

func cmdNetworkDNSProfileSet(env *Env, args []string) error {
	fs := newFlagSet(env, "network dns profile set")
	common := addEditFlags(fs)
	members := fs.String("members", "", "profile girecek cihazlar, tag:etiket veya group:grup, virgülle (zorunlu)")
	safe := fs.Bool("safe-search", false, "arama motorlarında güvenli aramayı zorla")
	noList := fs.Bool("no-blocklist", false, "bu cihazlara hiçbir engel listesi uygulama")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	if !trust.ValidDNSProfileName(name) {
		return usageError("profil adı küçük harfli bir DNS etiketi olmalı, ör. cocuk")
	}
	list := splitList(*members)
	if len(list) == 0 {
		return usageError("--members gerekli")
	}
	p := trust.DNSProfile{Name: name, Members: list, SafeSearch: *safe, NoBlocklist: *noList}
	fmt.Fprintln(env.Stdout, dnsProfileOldDevicesNote)
	fmt.Fprintf(env.Stdout, "Çıkış düğümünde profile özel liste için: openscale set exit-dns-profile-lists %s=/mutlak/yol\n", name)
	if *safe {
		fmt.Fprintln(env.Stdout, "Güvenli arama, çıkış düğümünde eşleme dosyası verilince zorlanır: openscale set exit-dns-safe-search-map /mutlak/yol")
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetDNSProfile(p) })
}

func cmdNetworkDNSProfileRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "network dns profile rm")
	common := addEditFlags(fs)
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	return runEdit(env, common, func(doc *trust.Document) error { return doc.RemoveDNSProfile(name) })
}

func cmdNetworkDNSProfileList(env *Env, args []string) error {
	doc, err := loadDocument(env, args, "network dns profile list")
	if err != nil || doc == nil {
		return err
	}
	if len(doc.DNSProfiles) == 0 {
		fmt.Fprintln(env.Stdout, "DNS profili yok; bütün cihazlara çıkış düğümünün varsayılan listesi uygulanır.")
		return nil
	}
	fmt.Fprintln(env.Stdout, "DNS profilleri (bir cihaza ilk eşleşen profil uygulanır):")
	for i, p := range doc.DNSProfiles {
		fmt.Fprintf(env.Stdout, "  %d. %s\n", i+1, admin.DNSProfileString(p))
	}
	return nil
}
