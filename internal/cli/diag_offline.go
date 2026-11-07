package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

// cmdPacketTrace explains how the rules treat one new connection (F-187).
// With --dir (the owner's network folder) or --member-dir (a member's
// state folder) it works from that document without a running tunnel;
// otherwise the running tunnel answers with the document it enforces.
func cmdPacketTrace(env *Env, args []string) error {
	fs := newFlagSet(env, "packet-trace")
	df := addDiagFlags(fs)
	netDir := fs.String("dir", "", "tünel yerine bu ağ klasöründeki belgeyle hesapla (yönetici cihaz)")
	memberDir := fs.String("member-dir", "", "tünel yerine bu üye durum klasöründeki belgeyle hesapla")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale packet-trace <kaynak> <hedef> <tcp|udp|icmp|numara> [port] [--json]")
		fmt.Fprintln(env.Stderr, "Kaynak ve hedef cihaz adı veya ağ içi adres olabilir; hedef ağ dışı bir IP ise çıkış düğümü kuralı açıklanır.")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 3 || len(pos) > 4 {
		return usageError("kullanım: openscale packet-trace <kaynak> <hedef> <protokol> [port]")
	}
	req := panel.TraceRequest{Src: pos[0], Dst: pos[1], Proto: strings.ToLower(pos[2])}
	if len(pos) == 4 {
		p, err := strconv.Atoi(pos[3])
		if err != nil || p < 1 || p > 65535 {
			return usageError("port 1 ile 65535 arasında bir sayı olmalı")
		}
		req.Port = p
	}
	if *netDir != "" && *memberDir != "" {
		return usageError("--dir ve --member-dir birlikte kullanılamaz")
	}
	var res panel.TraceResult
	switch {
	case *netDir != "" || *memberDir != "":
		var doc *trust.Document
		if *netDir != "" {
			n, err := admin.Load(*netDir, env.adminOptions())
			if err != nil {
				return err
			}
			if doc, err = n.Document(); err != nil {
				return err
			}
		} else {
			store, err := member.Open(*memberDir)
			if err != nil {
				return err
			}
			doc = store.Document()
		}
		res, err = service.TracePacket(doc, "", false, req)
		if err != nil {
			return err
		}
	default:
		c, err := df.client(env)
		if err != nil {
			return fmt.Errorf("%w\n(Tünel olmadan hesaplamak için --dir <ağ klasörü> verin.)", err)
		}
		if err := c.post(env, "/trace", req, &res); err != nil {
			return err
		}
	}
	if *df.json {
		return printJSON(env.Stdout, res)
	}
	w := env.Stdout
	target := res.Proto
	if res.Port > 0 {
		target += "/" + strconv.Itoa(res.Port)
	}
	fmt.Fprintf(w, "Paket: %s -> %s %s (yeni bağlantı)\n\n", res.Src, res.Dst, target)
	for _, s := range res.Steps {
		fmt.Fprintf(w, "  %-14s %-11s %s\n", s.Stage, s.Outcome, s.Detail)
	}
	fmt.Fprintf(w, "\nSonuç: %s\n", res.Verdict)
	return nil
}

// Limits of "debug fake-device".
const maxFakeTags = 8

// cmdDebugFakeDevice previews adding a made-up device (F-186): it shows
// the document change and what the device could reach, for testing rules.
// Only --dry-run exists; nothing is ever signed or written.
func cmdDebugFakeDevice(env *Env, args []string) error {
	fs := newFlagSet(env, "debug fake-device")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	dryRun := fs.Bool("dry-run", false, "yalnızca önizleme (zorunlu; gerçek belgeye hiçbir şey yazılmaz)")
	tags := fs.String("tags", "", "sahte cihazın etiketleri, virgülle (ör. sunucu,ev)")
	jsonOut := fs.Bool("json", false, "makine okunur JSON çıktı (\"schema\": 1)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("bir cihaz adı yazın: openscale debug fake-device <ad> --dry-run --dir <ağ klasörü>")
	}
	if !*dryRun {
		return usageError("sahte cihaz yalnızca --dry-run ile önizlenir; gerçek belgeye sahte cihaz eklenmez")
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	name := trust.SanitizeHostname(pos[0])
	if name == "" || name != pos[0] {
		return usageError("cihaz adı küçük harf, rakam ve tire içermeli (ör. test-sunucu)")
	}
	var tagList []string
	for _, t := range strings.Split(*tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tagList = append(tagList, t)
		}
	}
	if len(tagList) > maxFakeTags {
		return usageError("en fazla %d etiket", maxFakeTags)
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	now := env.Now()
	// Throwaway keys that exist only in memory for this preview.
	secrets, err := trust.GenerateDeviceSecrets(env.Random, now)
	if err != nil {
		return err
	}
	_, req, err := secrets.NewEnrollmentRequest(name, now)
	if err != nil {
		return err
	}
	var added trust.Device
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		d, err := doc.AddDevice(req, name, nil, now, trust.DefaultDeviceLife)
		if err != nil {
			return err
		}
		if len(tagList) > 0 {
			if err := doc.SetDeviceTags(name, tagList); err != nil {
				return err
			}
			d, _ = doc.DeviceByName(name)
		}
		added = d
		return nil
	})
	if err != nil {
		return err
	}
	var peers []string
	for _, p := range plan.Next.PeersOf(name) {
		peers = append(peers, p.Name)
	}
	if *jsonOut {
		return printJSON(env.Stdout, map[string]any{
			"schema": panel.DiagSchema, "dry_run": true, "name": added.Name, "ipv4": added.IPv4.String(), "ipv6": added.IPv6.String(),
			"tags": added.Tags, "version": plan.Next.Version, "changes": plan.Diff.Lines(), "peers": nonNil(peers),
		})
	}
	w := env.Stdout
	fmt.Fprintf(w, "Sahte cihaz önizlemesi (belge sürümü %d olurdu):\n", plan.Next.Version)
	fmt.Fprintf(w, "  %s.%s  %s  %s\n", added.Name, plan.Next.DNSDomain, added.IPv4, added.IPv6)
	if len(added.Tags) > 0 {
		fmt.Fprintf(w, "  etiketler: %s\n", strings.Join(added.Tags, ", "))
	}
	fmt.Fprintln(w, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintf(w, "  %s\n", line)
	}
	if len(peers) == 0 {
		fmt.Fprintln(w, "Kurallar bu cihazı hiçbir cihazla eşleştirmiyor.")
	} else {
		fmt.Fprintf(w, "Eşleşeceği cihazlar: %s\n", strings.Join(peers, ", "))
	}
	fmt.Fprintf(w, "Kuralları denemek için: openscale packet-trace %s <hedef> tcp 22 --dir %s (sahte cihaz belgede olmadığı için önce gerçek bir cihazla deneyin)\n", name, *dir)
	fmt.Fprintln(w, "Kuru çalıştırma: hiçbir şey imzalanmadı, anahtarlar atıldı.")
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
