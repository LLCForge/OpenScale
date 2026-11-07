package cli

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/netreport"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// cmdNetworkReport writes the readable network report (#553).
func cmdNetworkReport(env *Env, args []string) error {
	fs := newFlagSet(env, "network report")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	asHTML := fs.Bool("html", false, "tek dosyalık HTML sayfası (varsayılan Markdown)")
	asJSON := fs.Bool("json", false, "raporun verisi JSON olarak")
	out := fs.String("out", "", "yazılacak dosya (varsa üzerine yazılmaz; boş: ekrana)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	if *asHTML && *asJSON {
		return usageError("--html ve --json birlikte kullanılmaz")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	rep := netreport.Build(doc, env.Now())
	if *asJSON {
		return printJSON(env.Stdout, rep)
	}
	text := netreport.Markdown(rep)
	if *asHTML {
		if text, err = netreport.HTML(rep); err != nil {
			return err
		}
	}
	if *out == "" {
		_, err := fmt.Fprint(env.Stdout, text)
		return err
	}
	if err := securefile.WriteNew(*out, []byte(text)); err != nil {
		return fmt.Errorf("rapor yazılamadı: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Ağ raporu yazıldı: %s\nRapor anahtar, parmak izi veya davet kodu içermez; cihaz adlarını, adreslerini ve kuralları içerir.\n", *out)
	return nil
}

// cmdTrafficHistory shows the hourly traffic history (#505).
func cmdTrafficHistory(env *Env, args []string) error {
	fs := newFlagSet(env, "traffic history")
	df := addDiagFlags(fs)
	hours := fs.Int("hours", 24, "kaç saatlik geçmiş (1-720)")
	var device string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		device, args = args[0], args[1:]
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *hours < 1 || *hours > 720 {
		return usageError("--hours 1-720 arasında olmalı")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("hours", fmt.Sprint(*hours))
	if device != "" {
		q.Set("device", device)
	}
	var rep panel.TrafficHistoryReply
	if err := c.get(env, "/traffic-history?"+q.Encode(), &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	w := env.Stdout
	if device == "" {
		if len(rep.Devices) == 0 {
			fmt.Fprintln(w, "Henüz trafik geçmişi yok; servis çalıştıkça saatlik toplamlar birikir.")
			return nil
		}
		sort.Slice(rep.Devices, func(i, j int) bool {
			return rep.Devices[i].Rx+rep.Devices[i].Tx > rep.Devices[j].Rx+rep.Devices[j].Tx
		})
		fmt.Fprintf(w, "Son %d saat (yalnızca toplam bayt; hedef tutulmaz):\n", rep.Hours)
		fmt.Fprintf(w, "  %-24s %12s %12s\n", "CİHAZ", "GELEN", "GİDEN")
		for _, d := range rep.Devices {
			fmt.Fprintf(w, "  %-24s %12s %12s\n", d.Name, humanBytes(d.Rx), humanBytes(d.Tx))
		}
		return nil
	}
	var peak uint64
	for _, p := range rep.Points {
		peak = max(peak, p.Rx+p.Tx)
	}
	fmt.Fprintf(w, "%s, son %d saat (yerel saat):\n", device, rep.Hours)
	for _, p := range rep.Points {
		bar := ""
		if peak > 0 {
			bar = strings.Repeat("#", int((p.Rx+p.Tx)*30/peak))
		}
		fmt.Fprintf(w, "  %s  %10s gelen %10s giden  %s\n", p.Hour.In(env.Now().Location()).Format("01-02 15:00"), humanBytes(p.Rx), humanBytes(p.Tx), bar)
	}
	return nil
}

// cmdResources shows OpenScale's own resource use (#516).
func cmdResources(env *Env, args []string) error {
	fs := newFlagSet(env, "resources")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.ResourceReply
	if err := c.get(env, "/resources", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	w := env.Stdout
	s := rep.Summary
	if s.Samples == 0 {
		fmt.Fprintf(w, "Henüz ölçüm yok; servis her %d dakikada bir kendi tüketimini ölçer.\n", rep.SampleEverySeconds/60)
		return nil
	}
	fmt.Fprintf(w, "OpenScale'in kendi tüketimi (son %d ölçüm, %d dakikada bir):\n", s.Samples, rep.SampleEverySeconds/60)
	if s.CPUTimeKnown {
		fmt.Fprintf(w, "  İşlemci: ortalama %%%.2f, en yüksek %%%.2f (bir çekirdeğin yüzdesi)\n", s.AvgCPUPercent, s.MaxCPUPercent)
	} else {
		fmt.Fprintln(w, "  İşlemci: bu sistemde işlem süresi okunamıyor")
	}
	fmt.Fprintf(w, "  Bellek: en çok %s yığın, sistemden alınan %s\n", humanBytes(s.MaxHeapBytes), humanBytes(s.LastSysBytes))
	if s.BatteryShare != nil {
		fmt.Fprintf(w, "  Pil: ölçümlerin %%%.0f'i pildeyken; pildeyken kullanılan işlemci süresi %.1f saniye\n", *s.BatteryShare*100, s.CPUSecondsOnBattery)
	} else {
		fmt.Fprintln(w, "  Pil: bu bilgisayarda pil bulunamadı")
	}
	return nil
}
