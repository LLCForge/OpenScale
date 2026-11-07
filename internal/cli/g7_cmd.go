package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/adblock"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/plugin"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Blocking and plugin commands (ADR-0220, G7). Signed settings change
// through the network directory and the root key passphrase; the exit
// node downloads the approved lists into its own state directory.

func init() {
	registerCommands(
		command{"blocking show", "İmzalı engelleme ayarını ve eklenti sabitlemelerini gösterir: --dir <ağ klasörü> [--json]", cmdBlockingShow},
		command{"blocking set", "Engelleme ayarını JSON dosyasından imzalar (abonelik özetleri, kategori politikası, keep, DoH adları): --dir <ağ> --file <ayar.json> [--dry-run] [--passphrase-file]", cmdBlockingSet},
		command{"blocking digest", "Bir engel listesinin SHA-256 özetini ve ad sayısını gösterir (aboneliği onaylamadan önce): <dosya> --category <ads|trackers|miners|iot|os-telemetry>", cmdBlockingDigest},
		command{"blocking update", "Çıkış düğümünde onaylı listeleri indirir ve özetlerini doğrular: [--state-dir]", cmdBlockingUpdate},
		command{"plugin list", "Eklenti klasöründeki eklentileri, gizlilik etiketlerini ve özetlerini listeler: [--state-dir] [--json]", cmdPluginList},
		command{"plugin pin", "Eklentinin modül ve bildirge özetini imzalı belgeye sabitler: <ad> --dir <ağ> --plugins <klasör> [--dry-run] [--passphrase-file]", cmdPluginPin},
		command{"plugin unpin", "Eklenti sabitlemesini imzalı belgeden kaldırır: <ad> --dir <ağ> [--dry-run] [--passphrase-file]", cmdPluginUnpin},
	)
}

const maxBlockingFile = 256 << 10

type blockingShowJSON struct {
	Schema   int                     `json:"schema"`
	Version  uint64                  `json:"version"`
	Blocking *trust.BlockingSettings `json:"blocking"`
	Plugins  []trust.PluginPin       `json:"plugins"`
}

func cmdBlockingShow(env *Env, args []string) error {
	fs := newFlagSet(env, "blocking show")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	if *asJSON {
		out := blockingShowJSON{Schema: 1, Version: doc.Version, Blocking: doc.Blocking, Plugins: doc.Plugins}
		if out.Plugins == nil {
			out.Plugins = []trust.PluginPin{}
		}
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	b := doc.Blocking
	if b == nil {
		fmt.Fprintln(env.Stdout, "Engelleme: kapalı (imzalı belgede ayar yok).")
	} else {
		fmt.Fprintf(env.Stdout, "Engelleme: açık (belge sürüm %d)\n", doc.Version)
		for _, s := range b.Subscriptions {
			fmt.Fprintf(env.Stdout, "  abonelik  %-12s %s  %s…\n", s.Category, s.URL, s.SHA256[:16])
		}
		if b.Policy != nil {
			fmt.Fprintf(env.Stdout, "  varsayılan kategoriler: %s\n", categoryNames(b.Policy.Default))
			for tag, set := range b.Policy.Tags {
				fmt.Fprintf(env.Stdout, "  etiket %s: %s\n", tag, categoryNames(set))
			}
			for dev, set := range b.Policy.Devices {
				fmt.Fprintf(env.Stdout, "  cihaz %s: %s\n", dev, categoryNames(set))
			}
		}
		fmt.Fprintf(env.Stdout, "  keep: %d ad, DoH engeli: %d ad, .onion: NXDOMAIN\n", len(b.Keep), len(b.BlockDoH))
	}
	if len(doc.Plugins) == 0 {
		fmt.Fprintln(env.Stdout, "Sabitlenmiş eklenti yok.")
	}
	for _, p := range doc.Plugins {
		fmt.Fprintf(env.Stdout, "Eklenti %s  modül %s…  bildirge %s…\n", p.Name, p.ModuleSHA256[:16], p.ManifestSHA256[:16])
	}
	return nil
}

func categoryNames(s adblock.CategorySet) string {
	var names []string
	for _, c := range s.List() {
		names = append(names, c.String())
	}
	if len(names) == 0 {
		return "yok"
	}
	return strings.Join(names, ", ")
}

func cmdBlockingSet(env *Env, args []string) error {
	fs := newFlagSet(env, "blocking set")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	file := fs.String("file", "", "engelleme ayarı JSON dosyası (zorunlu; boş nesne ayarı kaldırır)")
	dry := fs.Bool("dry-run", false, "yalnızca farkı göster, imzalama")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *file == "" {
		return usageError("--file zorunlu")
	}
	data, err := securefile.ReadLimited(*file, maxBlockingFile)
	if err != nil {
		return fmt.Errorf("ayar dosyası okunamadı: %w", err)
	}
	var b trust.BlockingSettings
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return fmt.Errorf("ayar dosyası geçersiz: %w", err)
	}
	return g7Sign(env, *dir, *passFile, *dry, func(doc *trust.Document) error { return doc.SetBlocking(&b) })
}

// g7Sign shows the difference and signs it unless dry.
func g7Sign(env *Env, dir, passFile string, dry bool, fn func(*trust.Document) error) error {
	n, err := loadNetwork(env, dir)
	if err != nil {
		return err
	}
	plan, err := n.Prepare(env.Now(), trust.DefaultValidity, fn)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintln(env.Stdout, "  "+line)
	}
	if dry {
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: imzalanmadı.")
		return nil
	}
	pass, err := existingPassphrase(env, passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := n.Commit(plan, pass); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Belge sürüm %d imzalandı.\n", plan.Next.Version)
	return nil
}

func cmdBlockingDigest(env *Env, args []string) error {
	fs := newFlagSet(env, "blocking digest")
	category := fs.String("category", "", "listenin kategorisi (zorunlu)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *category == "" {
		return usageError("kullanım: openscale blocking digest <dosya> --category <kategori>")
	}
	data, err := securefile.ReadLimited(pos[0], adblock.MaxDownloadSize)
	if err != nil {
		return err
	}
	a, err := adblock.VerifyContent(*category, plugin.Digest(data), data)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "sha256 %s\nkategori %s, %d ad, %d satır atlandı, %d bayt\n", a.SHA256, a.Category, a.Names, a.Skipped, a.Size)
	return nil
}

func cmdBlockingUpdate(env *Env, args []string) error {
	fs := newFlagSet(env, "blocking update")
	stateDir := fs.String("state-dir", "", "cihaz durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	store, secrets, err := deviceState(env, *stateDir)
	if err != nil {
		return err
	}
	doc := store.Document()
	self, err := selfDevice(doc, secrets)
	if err != nil {
		return err
	}
	isExit := self.HasRole(trust.RoleExitNode)
	if !isExit {
		return errors.New("listeler yalnızca çıkış düğümü rolündeki cihazda indirilir")
	}
	lists, err := node.UpdateExitBlocklists(envContext(env), store.Dir(), doc, isExit)
	for _, a := range lists {
		fmt.Fprintf(env.Stdout, "  %-12s %d ad  %s…\n", a.Category, a.Names, a.SHA256[:16])
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Listeler indirildi ve doğrulandı; çözücü bir sonraki belge güncellemesinde veya yeniden başlatmada yükler.")
	return nil
}

func cmdPluginList(env *Env, args []string) error {
	fs := newFlagSet(env, "plugin list")
	stateDir := fs.String("state-dir", "", "cihaz durum klasörü")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	sd, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	var pins plugin.PinList
	if store, err := member.Open(sd); err == nil && store.Document() != nil {
		pins = node.PluginPins(store.Document())
	}
	st, err := plugin.LoadStoreDir(filepath.Join(sd, plugin.DirName), pins)
	if err != nil {
		return err
	}
	entries := st.Entries()
	if *asJSON {
		if entries == nil {
			entries = []plugin.Entry{}
		}
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	if len(entries) == 0 {
		fmt.Fprintf(env.Stdout, "Eklenti yok (%s).\n", filepath.Join(sd, plugin.DirName))
		return nil
	}
	for _, e := range entries {
		fmt.Fprintf(env.Stdout, "%s %s  [%s]\n", e.Name, e.Version, e.StatusLabel)
		fmt.Fprintf(env.Stdout, "  görür: %s\n", strings.Join(e.DataLabels, ", "))
		fmt.Fprintf(env.Stdout, "  kancalar: %s, hata durumunda: %s, %d MiB, %d ms\n", strings.Join(e.Hooks, ", "), e.OnError, e.MemoryLimitMiB, e.CallTimeoutMS)
		fmt.Fprintf(env.Stdout, "  modül %s\n  bildirge %s\n", e.ModuleSHA256, e.ManifestSHA256)
		if e.Reason != "" {
			fmt.Fprintf(env.Stdout, "  neden: %s\n", e.Reason)
		}
	}
	return nil
}

func cmdPluginPin(env *Env, args []string) error {
	fs := newFlagSet(env, "plugin pin")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	from := fs.String("plugins", "", "eklentinin .wasm ve .json dosyalarının klasörü (zorunlu)")
	dry := fs.Bool("dry-run", false, "yalnızca farkı göster, imzalama")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *from == "" {
		return usageError("kullanım: openscale plugin pin <ad> --dir <ağ> --plugins <klasör>")
	}
	name := pos[0]
	pin := trust.PluginPin{Name: name}
	for _, ext := range []string{".wasm", ".json"} {
		data, err := securefile.ReadLimited(filepath.Join(*from, name+ext), 16<<20)
		if err != nil {
			return fmt.Errorf("%s%s okunamadı: %w", name, ext, err)
		}
		if ext == ".json" {
			m, err := plugin.ParseManifest(data)
			if err != nil {
				return err
			}
			if m.Name != name {
				return fmt.Errorf("bildirgedeki ad %q, dosya adıyla uyuşmuyor", m.Name)
			}
			fmt.Fprintf(env.Stdout, "Eklenti %s görecek: %s\n", name, strings.Join(m.DataLabels(), ", "))
			pin.ManifestSHA256 = plugin.Digest(data)
		} else {
			pin.ModuleSHA256 = plugin.Digest(data)
		}
	}
	return g7Sign(env, *dir, *passFile, *dry, func(doc *trust.Document) error { return doc.SetPluginPin(pin) })
}

func cmdPluginUnpin(env *Env, args []string) error {
	fs := newFlagSet(env, "plugin unpin")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	dry := fs.Bool("dry-run", false, "yalnızca farkı göster, imzalama")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("kullanım: openscale plugin unpin <ad> --dir <ağ>")
	}
	name := pos[0]
	return g7Sign(env, *dir, *passFile, *dry, func(doc *trust.Document) error { return doc.RemovePluginPin(name) })
}
