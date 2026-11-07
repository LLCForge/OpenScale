package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/updater"
)

// Members-only documents (blind coordinator, #629, ADR-0178), the way past an
// administrator's versions (ADR-0172) and the stored release revocation list
// (ADR-0022, ADR-0195).

func init() { registerCommands(f1Commands()...) } // g4_registry.go

func f1Commands() []command {
	return []command{
		{"network members-only", "Kör koordinatör kipi: belgedeki adlar, etiketler ve kurallar yalnızca üyelere mühürlenir: --dir AĞ (--set on|off | --show) [--dry-run]", cmdNetworkMembersOnly},
		{"admin overtake", "Sonraki kök sürümünü yöneticilerin imzalayabileceği her sürümün üstüne taşır (üyeler kök belgesini geri alma diye reddediyorsa): --dir AĞ", cmdAdminOvertake},
		{"update revocations", "Kök imzalı sürüm iptal listesini bu cihaza kaydeder veya gösterir; listedeki anahtarlar güncellemede ve açılışta reddedilir: (--file DOSYA | --show) [--root-key ANAHTAR]", cmdUpdateRevocations},
	}
}

func cmdNetworkMembersOnly(env *Env, args []string) error {
	fs := newFlagSet(env, "network members-only")
	common := addEditFlags(fs)
	var set onOffFlag
	fs.Var(&set, "set", "kipi aç veya kapat (on|off) ve yeni sürümü imzala")
	show := fs.Bool("show", false, "yalnızca durumu göster")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *common.dir == "" {
		return usageError("--dir zorunlu")
	}
	if *show == set.set {
		return usageError("--set veya --show verin (yalnızca biri)")
	}
	if *common.draft {
		return usageError("bu ayar taslağa eklenemez")
	}
	validity, err := daysFlag(*common.validityDays, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	n, err := admin.Load(*common.dir, env.adminOptions())
	if err != nil {
		return err
	}
	st, err := n.MembersOnlyState()
	if err != nil {
		return err
	}
	if *show {
		fmt.Fprintf(env.Stdout, "Üyelere mühürlü belge: %s\n", onOff(st.Enabled))
		fmt.Fprintf(env.Stdout, "Yayımlanan belge mühürlü: %s\n", onOff(st.Sealed))
		fmt.Fprintf(env.Stdout, "Asgari istemci sürümü: %s (gereken %s)\n", versionOrDash(st.MinClientVersion), st.RequiredClientVersion)
		printMembersOnlyNotes(env, st)
		return nil
	}
	if set.value {
		if len(st.Blockers) > 0 {
			printMembersOnlyNotes(env, st)
			return errors.New("kör koordinatör kipi şu an açılamaz")
		}
		printMembersOnlyNotes(env, st)
	}
	plan, err := n.PrepareMembersOnly(set.value, env.Now(), validity)
	if errors.Is(err, admin.ErrMembersOnlyUnchanged) {
		fmt.Fprintf(env.Stdout, "Üyelere mühürlü belge zaten %s; imzalanacak bir şey yok.\n", onOff(set.value))
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
	if *common.dryRun {
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: hiçbir şey imzalanmadı.")
		return nil
	}
	passphrase, err := existingPassphrase(env, *common.passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	if err := n.CommitMembersOnly(set.value, plan, func(p *admin.Plan) error { return n.Commit(p, passphrase) }); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Üyelere mühürlü belge %s; ağ belgesi sürüm %d olarak imzalandı.\n", onOff(set.value), plan.Next.Version)
	if set.value {
		fmt.Fprintln(env.Stdout, "Koordinatörün de kör çalışması için sunucuda: openscale coordinator harden --blind on")
	}
	return nil
}

func printMembersOnlyNotes(env *Env, st admin.MembersOnlyStatus) {
	for _, b := range st.Blockers {
		fmt.Fprintf(env.Stdout, "ENGEL: %s\n", b)
	}
	for _, w := range st.Warnings {
		fmt.Fprintf(env.Stdout, "UYARI: %s\n", w)
	}
}

func versionOrDash(v string) string {
	if v == "" {
		return "yok"
	}
	return v
}

func cmdAdminOvertake(env *Env, args []string) error {
	fs := newFlagSet(env, "admin overtake")
	common := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return runEdit(env, common, admin.OvertakeAdminVersions())
}

func cmdUpdateRevocations(env *Env, args []string) error {
	fs := newFlagSet(env, "update revocations")
	file := fs.String("file", "", "kök imzalı iptal listesi dosyası")
	show := fs.Bool("show", false, "bu cihazda geçerli listeyi göster")
	rootKey := fs.String("root-key", "", "sürüm kök açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...); varsayılan: gömülü anahtar")
	stateDir := fs.String("update-dir", "", "güncelleme klasörü (varsayılan: platformunki)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *show == (*file != "") {
		return usageError("--file veya --show verin (yalnızca biri)")
	}
	dir := *stateDir
	if dir == "" {
		p, err := updater.DefaultPlatform()
		if err != nil {
			return err
		}
		dir = p.StateDir
	}
	root, _, err := updater.LoadRootKey(*rootKey)
	if err != nil {
		return err
	}
	if *show {
		list, err := updater.KnownRevocations(dir, root)
		if err != nil {
			return err
		}
		if list == nil {
			fmt.Fprintln(env.Stdout, "Bu cihazda imzalı iptal listesi yok.")
			return nil
		}
		printRevocations(env, list)
		return nil
	}
	if *stateDir == "" {
		if err := updater.RequirePrivileges(); err != nil {
			return err
		}
	}
	data, err := securefile.ReadLimited(*file, release.MaxRevocationsSize)
	if err != nil {
		return err
	}
	list, err := updater.InstallRevocations(dir, root, data)
	if err != nil {
		return err
	}
	printRevocations(env, list)
	fmt.Fprintln(env.Stdout, "Liste kaydedildi; güncellemede ve açılış denetiminde uygulanır. Kurulu sürümün imzalama anahtarı listedeyse servis bir sonraki açılışta başlamaz.")
	return nil
}

func printRevocations(env *Env, list *release.Revocations) {
	fmt.Fprintf(env.Stdout, "İptal listesi: sıra %d, %s, %d anahtar\n", list.Sequence, list.Issued.Format("2006-01-02"), len(list.Revoked))
	for _, k := range list.Revoked {
		fmt.Fprintf(env.Stdout, "  %s %s\n", k.SigningKey.Fingerprint(), strings.TrimSpace(k.Reason))
	}
}
