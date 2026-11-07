package cli

import (
	"fmt"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

// unmarshalDeviceKey reads a device key that is either plain or sealed to
// this computer's TPM (#602, ADR-0208). The opened copy is wiped.
func unmarshalDeviceKey(data []byte) (*trust.DeviceSecrets, error) {
	plain, sealed, err := tpm.UnwrapDeviceKey(data)
	if err != nil {
		return nil, err
	}
	if sealed {
		defer clear(plain)
	}
	return trust.UnmarshalDeviceSecrets(plain)
}

func init() { registerCommands(wireTPMCommands()...) }

func wireTPMCommands() []command {
	return []command{
		{"tpm seal-device-key", "Cihaz anahtarını bu bilgisayarın TPM'ine mühürler (eski dosya yedeklenir): [--state-dir KLASÖR] --yes", cmdTPMSealDeviceKey},
		{"tpm key-status", "Cihaz anahtarının TPM ile mühürlü olup olmadığını gösterir: [--state-dir KLASÖR]", cmdTPMKeyStatus},
	}
}

// deviceKeyBackupSuffix names the copy of the unsealed key kept next to
// device.key: it has the same protection as before (securefile), so
// sealing never leaves the device without a working key.
const deviceKeyBackupSuffix = ".muhur-oncesi"

func cmdTPMSealDeviceKey(env *Env, args []string) error {
	fs := newFlagSet(env, "tpm seal-device-key")
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	yes := fs.Bool("yes", false, "onay: anahtar yalnızca bu bilgisayarda açılabilir olur")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !*yes {
		return usageError("mühürlenen anahtar başka bilgisayarda ve TPM sıfırlanınca açılamaz; onaylamak için --yes")
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, deviceKeyFile)
	data, err := securefile.ReadPrivate(path, trust.MaxDeviceKeySize)
	if err != nil {
		return err
	}
	defer wipe(data)
	if _, err := trust.UnmarshalDeviceSecrets(data); err != nil {
		return fmt.Errorf("cihaz anahtarı okunamadı veya zaten mühürlü: %w", err)
	}
	env2, err := tpm.SealDeviceKey(data, nil)
	if err != nil {
		return fmt.Errorf("mühürleme yapılmadı, anahtar değişmedi: %w", err)
	}
	if err := securefile.WriteNew(path+deviceKeyBackupSuffix, data); err != nil {
		return fmt.Errorf("yedek yazılamadı, anahtar değişmedi: %w", err)
	}
	if err := securefile.Replace(path, env2); err != nil {
		return err
	}
	if _, err := readSecrets(path); err != nil {
		return fmt.Errorf("mühürlü anahtar okunamadı; yedekten geri yükleyin (%s): %w", path+deviceKeyBackupSuffix, err)
	}
	fmt.Fprintln(env.Stdout, "Cihaz anahtarı TPM ile mühürlendi.")
	fmt.Fprintf(env.Stdout, "Eski koruma ile yedek: %s (denedikten sonra güvenle silebilirsiniz).\n", path+deviceKeyBackupSuffix)
	return nil
}

func cmdTPMKeyStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "tpm key-status")
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, deviceKeyFile), trust.MaxDeviceKeySize)
	if err != nil {
		return err
	}
	defer wipe(data)
	if ok, kind := tpm.SealedKind(data); ok {
		fmt.Fprintf(env.Stdout, "Cihaz anahtarı mühürlü (%s).\n", orDash(kind))
		return nil
	}
	fmt.Fprintln(env.Stdout, "Cihaz anahtarı mühürlü değil.")
	return nil
}
