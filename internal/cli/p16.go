package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel/web"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Panel and usability commands (P16): the first-run wizard (#225), the
// offline documentation (#237) and signed document export/import (#234).

func p16Commands() []command {
	return []command{
		{"setup", "İlk kurulum sihirbazı: ağ, kök anahtar yedeği, koordinatör ve ilk cihaz adım adım", cmdSetup},
		{"docs", "Çevrimdışı kullanım ve güvenlik rehberini gösterir: [konu] (konusuz: liste)", cmdDocs},
		{"network export", "İmzalı ağ belgesini dosyaya yazar (gizli anahtar içermez, yedek değildir)", cmdNetworkExport},
		{"network import", "İmzalı bir ağ belgesini doğrular ve mevcut sürümle farkını gösterir (hiçbir şey yazmaz)", cmdNetworkImport},
	}
}

// --- openscale setup (#225) ---

type setupState struct {
	network     bool
	backups     int
	coordinator bool
	devices     int
	invites     int
}

func readSetupState(env *Env, dir string) (setupState, error) {
	var st setupState
	if _, err := os.Stat(filepath.Join(dir, "root.key")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	n, err := admin.Load(dir, env.adminOptions())
	if err != nil {
		return st, err
	}
	st.network = true
	backups, err := n.Backups()
	if err != nil {
		return st, err
	}
	st.backups = len(backups)
	doc, err := n.Document()
	if err != nil {
		return st, err
	}
	st.coordinator = doc.Coordinator != nil
	st.devices = len(doc.Devices)
	st.invites = len(doc.Invites)
	return st, nil
}

func printSetupPlan(env *Env, st setupState) {
	mark := func(done bool) string {
		if done {
			return "[tamam]"
		}
		return "[ yapılacak ]"
	}
	w := env.Stdout
	fmt.Fprintln(w, "OpenScale ilk kurulum adımları:")
	fmt.Fprintf(w, "  1. Ağ ve kök anahtar             %s\n", mark(st.network))
	fmt.Fprintf(w, "  2. Kök anahtar yedeği            %s\n", mark(st.backups > 0))
	fmt.Fprintf(w, "  3. Koordinatör                   %s\n", mark(st.coordinator))
	fmt.Fprintf(w, "  4. İlk cihaz (davet veya kayıt)  %s\n", mark(st.devices > 0 || st.invites > 0))
	printMissingSteps(w, st) // #792, f2_setup_resume.go
}

// askYes asks a yes/no question; an empty answer takes def.
func askYes(env *Env, question string, def bool) (bool, error) {
	hint := " [E/h]: "
	if !def {
		hint = " [e/H]: "
	}
	answer, err := env.ReadLine(question + hint)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "":
		return def, nil
	case "e", "evet", "y", "yes":
		return true, nil
	case "h", "hayır", "hayir", "n", "no":
		return false, nil
	}
	return false, usageError("yanıt anlaşılamadı: e (evet) veya h (hayır) yazın")
}

func askLine(env *Env, prompt string) (string, error) {
	answer, err := env.ReadLine(prompt)
	return strings.TrimSpace(answer), err
}

func cmdSetup(env *Env, args []string) error {
	fs := newFlagSet(env, "setup")
	dir := fs.String("dir", "", "ağ klasörü; ağ yoksa burada oluşturulur (zorunlu)")
	planOnly := fs.Bool("plan", false, "yalnızca adımların durumunu göster, hiçbir şey değiştirme")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	st, err := readSetupState(env, *dir)
	if err != nil {
		return err
	}
	printSetupPlan(env, st)
	if *planOnly {
		return nil
	}
	if !env.IsTerminal() {
		return usageError("kurulum sihirbazı soru sorar; bir terminalde çalıştırın (adımları görmek için: openscale setup --dir %s --plan)", *dir)
	}
	w := env.Stdout
	progress := readSetupProgress(*dir) // #792: resume where the last run stopped
	printResumeNote(w, st, progress)

	if !st.network {
		fmt.Fprintln(w, "\n1/4  Ağ ve kök anahtar")
		fmt.Fprintln(w, "Kök anahtar ağın tek yetkilisidir; bu bilgisayarda parolayla şifrelenip saklanır.")
		ok, err := askYes(env, "Ağ şimdi bu klasörde oluşturulsun mu?", true)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(w, "Kurulum durduruldu; hiçbir şey değişmedi.")
			return nil
		}
		// The backup is part of creating the network (#195): "network init
		// --backup-out" writes it and opens it again to verify it.
		fmt.Fprintln(w, "\n2/4  Kök anahtar yedeği")
		fmt.Fprintln(w, "Yedek ayrı bir parolayla şifrelenir. Bir USB belleğe veya başka bir diske yaz; bu bilgisayar bozulursa ağ yedekten geri gelir.")
		out, err := askLine(env, "Yedek dosyasının yolu (boş bırakırsan yedek sonraya kalır): ")
		if err != nil {
			return err
		}
		initArgs := []string{"--dir", *dir, "--skip-backup"}
		if out != "" {
			initArgs = []string{"--dir", *dir, "--backup-out", out}
		}
		if err := cmdNetworkInit(env, initArgs); err != nil {
			return err
		}
		progress.mark(setupStepBackup, out == "")
		saveSetupProgress(env, *dir, progress)
	} else if st.backups == 0 {
		fmt.Fprintln(w, "\n2/4  Kök anahtar yedeği")
		fmt.Fprintln(w, "Yedek ayrı bir parolayla şifrelenir. Bir USB belleğe veya başka bir diske yaz; bu bilgisayar bozulursa ağ yedekten geri gelir.")
		out, err := askLine(env, "Yedek dosyasının yolu (boş bırakırsan bu adım atlanır): ")
		if err != nil {
			return err
		}
		if out == "" {
			fmt.Fprintln(w, "Yedek atlandı. Daha sonra: openscale network backup --dir "+*dir+" --out <dosya>")
		} else if err := cmdNetworkBackup(env, []string{"--dir", *dir, "--out", out}); err != nil {
			return err
		}
		progress.mark(setupStepBackup, out == "")
		saveSetupProgress(env, *dir, progress)
	}

	if !st.coordinator {
		fmt.Fprintln(w, "\n3/4  Koordinatör")
		fmt.Fprintln(w, "Koordinatör cihazların birbirini bulmasını sağlar; ağın yetkisi yoktur. Sunucuda önce şunu çalıştır:")
		fmt.Fprintln(w, "  openscale coordinator keygen --dir <sunucudaki klasör>")
		endpoint, err := askLine(env, "Koordinatörün dış adresi, ör. vpn.ornek.com:51820 (boş: atla): ")
		if err != nil {
			return err
		}
		progress.mark(setupStepCoordinator, endpoint == "")
		saveSetupProgress(env, *dir, progress)
		if endpoint == "" {
			fmt.Fprintln(w, "Koordinatör atlandı. Daha sonra: openscale network set-coordinator --dir "+*dir)
		} else {
			key, err := askLine(env, "'coordinator keygen' çıktısındaki WireGuard açık anahtarı: ")
			if err != nil {
				return err
			}
			fp, err := askLine(env, "'coordinator keygen' çıktısındaki parmak izi: ")
			if err != nil {
				return err
			}
			if err := cmdNetworkSetCoordinator(env, []string{"--dir", *dir, "--endpoint", endpoint, "--wireguard-key", key, "--fingerprint", fp}); err != nil {
				return err
			}
		}
	}

	st, err = readSetupState(env, *dir)
	if err != nil {
		return err
	}
	if st.devices == 0 && st.invites == 0 {
		fmt.Fprintln(w, "\n4/4  İlk cihaz")
		if st.coordinator {
			ok, err := askYes(env, "İlk cihaz için tek kullanımlık davet kodu oluşturulsun mu?", true)
			if err != nil {
				return err
			}
			progress.mark(setupStepFirstDevice, !ok)
			saveSetupProgress(env, *dir, progress)
			if ok {
				if err := cmdInviteCreate(env, []string{"--dir", *dir}); err != nil {
					return err
				}
			}
		} else {
			fmt.Fprintln(w, "Koordinatör olmadan davet kullanılamaz. Cihazı çevrimdışı eklemek için cihazda:")
			fmt.Fprintln(w, "  openscale keygen --hostname <cihaz-adı>")
			fmt.Fprintln(w, "ve burada çıkan kayıt isteğiyle:")
			fmt.Fprintln(w, "  openscale device add --dir "+*dir+" --request <istek>")
		}
	}

	st, err = readSetupState(env, *dir)
	if err != nil {
		return err
	}
	fmt.Fprintln(w)
	printSetupPlan(env, st)
	fmt.Fprintln(w, "\nPanelde devam etmek için: openscale panel --dir "+*dir)
	return nil
}

// --- openscale docs (#237) ---

// helpDoc is one page of the offline documentation the panel build writes
// to yardim/docs.json (panel/scripts/copy-docs.mjs).
type helpDoc struct {
	Slug   string `json:"slug"`
	Title  string `json:"title"`
	Group  string `json:"group"`
	Source string `json:"source"`
	Body   string `json:"body"`
}

type helpBundle struct {
	Schema int       `json:"schema"`
	Docs   []helpDoc `json:"docs"`
}

// maxHelpBundle bounds the embedded documentation file.
const maxHelpBundle = 8 << 20

func loadHelp() (helpBundle, error) {
	var b helpBundle
	f, err := web.FS().Open("yardim/docs.json")
	if err != nil {
		return b, errors.New("bu ikiliye çevrimdışı belgeler gömülmemiş; 'pnpm --dir panel build' ve 'go build' ile yeniden derleyin")
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxHelpBundle))
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("gömülü belgeler okunamadı: %w", err)
	}
	return b, nil
}

func cmdDocs(env *Env, args []string) error {
	fs := newFlagSet(env, "docs")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() > 1 {
		return usageError("en fazla bir konu verilebilir")
	}
	b, err := loadHelp()
	if err != nil {
		return err
	}
	w := env.Stdout
	if fs.NArg() == 0 {
		fmt.Fprintln(w, "Çevrimdışı belgeler (internet gerekmez; panelde 'Yardım' sayfasında da var):")
		group := ""
		for _, d := range b.Docs {
			if d.Group != group {
				group = d.Group
				fmt.Fprintf(w, "\n%s\n", group)
			}
			fmt.Fprintf(w, "  %-34s %s\n", d.Slug, d.Title)
		}
		fmt.Fprintln(w, "\nBir konuyu okumak için: openscale docs <konu>")
		return nil
	}
	want := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	for _, d := range b.Docs {
		if d.Slug == want {
			fmt.Fprintln(w, d.Body)
			return nil
		}
	}
	return usageError("böyle bir konu yok: %q (liste için: openscale docs)", want)
}

// --- openscale network export / import (#234) ---

func cmdNetworkExport(env *Env, args []string) error {
	fs := newFlagSet(env, "network export")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	out := fs.String("out", "", "belgenin yazılacağı dosya (zorunlu; varsa üzerine yazılmaz)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		return usageError("--dir ve --out zorunlu")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	data, err := n.SignedDocument()
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("belge yazılamadı: %w", err)
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	fmt.Fprintf(env.Stdout, "İmzalı ağ belgesi (sürüm %d) yazıldı: %s\n", doc.Version, *out)
	fmt.Fprintf(env.Stdout, "SHA-256: %s\n", hex.EncodeToString(sum[:]))
	fmt.Fprintln(env.Stdout, "Bu dosya gizli anahtar içermez ve kök anahtarın yedeği değildir; yedek için: openscale network backup")
	return nil
}

func cmdNetworkImport(env *Env, args []string) error {
	fs := newFlagSet(env, "network import")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	file := fs.String("file", "", "doğrulanacak imzalı belge (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *file == "" {
		return usageError("--dir ve --file zorunlu")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	data, err := readLimited(*file, trust.MaxEnvelopeSize)
	if err != nil {
		return err
	}
	imported, err := n.InspectDocument(data)
	if err != nil {
		if errors.Is(err, admin.ErrForeignDocument) {
			return errors.New("belge başka bir ağa ait; hiçbir şey yapılmadı")
		}
		return fmt.Errorf("belge doğrulanamadı, hiçbir şey yapılmadı: %s", admin.Describe(err))
	}
	current, err := n.Document()
	if err != nil {
		return err
	}
	w := env.Stdout
	sum := sha256.Sum256(data)
	fmt.Fprintln(w, "İmza geçerli: belge bu ağın kök anahtarıyla imzalanmış.")
	fmt.Fprintf(w, "  Sürüm:            %d (şu anki: %d)\n", imported.Version, current.Version)
	fmt.Fprintf(w, "  İmzalandı:        %s\n", formatTime(imported.IssuedAt))
	fmt.Fprintf(w, "  Geçerlilik sonu:  %s\n", formatTime(imported.ExpiresAt))
	fmt.Fprintf(w, "  Cihaz / kural:    %d / %d\n", len(imported.Devices), len(imported.Rules))
	fmt.Fprintf(w, "  SHA-256:          %s\n", hex.EncodeToString(sum[:]))
	var diff admin.Diff
	switch {
	case imported.Version < current.Version:
		fmt.Fprintln(w, "\nBu eski bir sürüm. O sürümden bu yana değişenler:")
		diff = admin.ComputeDiff(imported, current)
	case imported.Version > current.Version:
		fmt.Fprintln(w, "\nUYARI: belge bu klasördekinden yeni. Ağ başka bir kopyadan yönetilmiş olabilir; 'openscale network verify' çalıştırın. Farklar:")
		diff = admin.ComputeDiff(current, imported)
	default:
		fmt.Fprintln(w, "\nBelge şu anki sürümle aynı sürüm numarasını taşıyor.")
		return nil
	}
	for _, line := range diff.Lines() {
		fmt.Fprintf(w, "  %s\n", line)
	}
	fmt.Fprintln(w, "\nHiçbir şey imzalanmadı veya yazılmadı. Eski bir sürüm geri yüklenmez: iptal edilmiş cihazları geri getirebilirdi.")
	return nil
}

func readLimited(path string, limit int) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s düzenli bir dosya değil", path)
	}
	if info.Size() > int64(limit) {
		return nil, errors.New("dosya bir ağ belgesi için çok büyük")
	}
	return os.ReadFile(path)
}

// --- explanatory errors (#230) ---

// errorHint adds what to do for errors whose cause the user can fix: no
// administrator rights and a port already in use (OS-230).
func errorHint(err error) string {
	if h := suggestionHint(err); h != "" { // #798, f2_suggest.go
		return h
	}
	switch {
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "Ne yapmalı: komutu yönetici olarak çalıştırın (Windows: 'Yönetici olarak çalıştır' ile açılan terminal; Linux/macOS: sudo openscale ...) veya dosyanın sahibini denetleyin."
	case errors.Is(err, syscall.EADDRINUSE), strings.Contains(strings.ToLower(err.Error()), "address already in use"),
		strings.Contains(err.Error(), "Only one usage of each socket address"),
		strings.Contains(err.Error(), "forbidden by its access permissions"):
		return "Ne yapmalı: port başka bir program tarafından kullanılıyor veya sistem tarafından ayrılmış. Çalışan başka bir openscale olup olmadığını denetleyin veya --port ile başka bir port (0: boş bir port) seçin."
	}
	return ""
}
