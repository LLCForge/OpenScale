package cli

import (
	"fmt"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/namesuggest"
)

// openscale device retire (#825): the retirement wizard of the command
// line. It shows everything that names the device, then revokes it and
// cleans every reference in one signed version (admin.RetireChange).

func init() {
	registerCommands(command{"device retire", "Cihazı emekliye ayırır: önce başvurduğu kuralları, grupları, DNS, çıkış zinciri, eşitleme/yedek, SSH ve WoL girdilerini gösterir, sonra tek imzada iptal edip temizler", cmdDeviceRetire})
}

func cmdDeviceRetire(env *Env, args []string) error {
	fs := newFlagSet(env, "device retire")
	common := addEditFlags(fs)
	name := fs.String("name", "", "emekliye ayrılacak cihaz (zorunlu)")
	confirm := fs.String("confirm", "", "betikler için açık onay: cihazın adı (iptal geri alınamaz)")
	asJSON := fs.Bool("json", false, "yalnızca önizlemeyi JSON olarak yaz, hiçbir şey imzalama")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *common.dir == "" {
		return usageError("--dir ve --name zorunlu")
	}
	n, err := admin.Load(*common.dir, env.adminOptions())
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	p, err := admin.PreviewRetire(doc, *name, env.Now())
	if err != nil {
		return namesuggest.Wrap(err, namesuggest.KindDevice, *name, knownDeviceNames(doc))
	}
	if *asJSON {
		return printJSON(env.Stdout, p)
	}
	printRetirePreview(env, p)
	if !*common.dryRun && (common.draft == nil || !*common.draft) {
		if err := confirmCritical(env, *confirm, p.Device, p.Device+" emekliye ayrılacak: anahtarları kalıcı olarak iptal edilir ve geri alınamaz"); err != nil {
			return err
		}
	}
	return runEdit(env, common, admin.RetireChange(p.Device, env.Now()))
}

func printRetirePreview(env *Env, p admin.RetirePreview) {
	w := env.Stdout
	fmt.Fprintf(w, "Emekliye ayrılacak cihaz: %s  %s  %s\n", p.Device, p.IPv4, p.IPv6)
	if len(p.Sections) == 0 {
		fmt.Fprintln(w, "Belgede bu cihaza başka başvuru yok.")
	}
	for _, s := range p.Sections {
		fmt.Fprintf(w, "\n%s:\n", s.Title)
		for _, it := range s.Items {
			mark := "-"
			if it.Cleaned {
				mark = "*"
			}
			fmt.Fprintf(w, "  %s %s\n      %s\n", mark, it.Title, it.Effect)
		}
	}
	fmt.Fprintf(w, "\nİmzayla birlikte temizlenecek girdi: %d (* ile işaretli)\n", p.Cleaned)
	for _, note := range p.Notes {
		fmt.Fprintf(w, "Not: %s\n", note)
	}
	fmt.Fprintln(w)
}
