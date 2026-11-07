package cli

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// Encrypted diagnostics bundles (#512, ADR-0166). The helper makes a key
// pair once and hands out the public half; the owner seals the bundle to
// it, so a bundle sent through mail or chat is readable only by the
// helper.

// maxSealedBundle bounds a sealed bundle read for opening.
const maxSealedBundle = bundlecrypt.MaxPlaintext + 1<<10

// maxBundleKeyFile bounds a key file.
const maxBundleKeyFile = 4 << 10

func bundleRecipient(text string) (*ecdh.PublicKey, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	p, err := bundlecrypt.ParsePublic(text)
	if err != nil {
		return nil, usageError("--to: %v", err)
	}
	return p, nil
}

func randomReader(env *Env) io.Reader {
	if env.Random != nil {
		return env.Random
	}
	return rand.Reader
}

// writeSealedBundle zips the bundle in memory, seals it and writes it.
func writeSealedBundle(env *Env, rep panel.BundleReply, to *ecdh.PublicKey, name string, force bool) error {
	var zipped bytes.Buffer
	if err := writeBundleZip(&zipped, rep); err != nil {
		return err
	}
	sealed, err := bundlecrypt.Seal(randomReader(env), to, zipped.Bytes())
	clear(zipped.Bytes())
	if err != nil {
		return err
	}
	if name == "" {
		name = "openscale-teshis-" + env.Now().Format("20060102-150405") + ".osb"
	}
	f, err := createOutput(name, force)
	if err != nil {
		return err
	}
	if _, err := f.Write(sealed); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s yazıldı (şifreli; alıcı anahtar parmak izi %s).\n", name, bundlecrypt.Fingerprint(to))
	fmt.Fprintln(env.Stdout, "Parmak izini yardım edecek kişiyle sesli karşılaştırın; yalnızca o kişi 'openscale debug bundle-open' ile açabilir.")
	return nil
}

func cmdBundleKey(env *Env, args []string) error {
	fs := newFlagSet(env, "debug bundle-key")
	out := fs.String("out", "", "özel anahtar dosyası (zorunlu; varsa üzerine yazılmaz)")
	show := fs.Bool("show", false, "var olan anahtar dosyasının açık anahtarını göster (--out ile)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError("--out zorunlu")
	}
	w := env.Stdout
	if *show {
		k, err := readBundleKey(*out)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Açık anahtar: %s\nParmak izi:   %s\n", k.PublicText(), bundlecrypt.Fingerprint(k.Private.PublicKey()))
		return nil
	}
	k, err := bundlecrypt.Generate(randomReader(env))
	if err != nil {
		return err
	}
	data, err := k.MarshalKeyFile()
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("anahtar dosyası yazılamadı: %w", err)
	}
	clear(data)
	fmt.Fprintf(w, "Alıcı anahtarı yazıldı: %s (yalnızca sizin okuyabileceğiniz bir dosya; kimseyle paylaşmayın).\n\n", *out)
	fmt.Fprintf(w, "Yardım isteyen kişiye bu açık anahtarı verin:\n\n  %s\n\nParmak izi: %s\n", k.PublicText(), bundlecrypt.Fingerprint(k.Private.PublicKey()))
	fmt.Fprintln(w, "\nO kişi: openscale debug bundle --to <açık anahtar>   Siz açarken: openscale debug bundle-open --key", *out, "-o paket.zip <dosya.osb>")
	return nil
}

func readBundleKey(path string) (*bundlecrypt.KeyPair, error) {
	data, err := securefile.ReadPrivate(path, maxBundleKeyFile)
	if err != nil {
		return nil, fmt.Errorf("anahtar dosyası okunamadı: %w", err)
	}
	defer clear(data)
	return bundlecrypt.ParseKeyFile(data)
}

func cmdBundleOpen(env *Env, args []string) error {
	fs := newFlagSet(env, "debug bundle-open")
	keyPath := fs.String("key", "", "'debug bundle-key' ile üretilen özel anahtar dosyası (zorunlu)")
	out := fs.String("o", "", "yazılacak zip dosyası (zorunlu)")
	force := fs.Bool("force", false, "var olan dosyanın üzerine yaz")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() != 1 {
		return usageError("şifreli paket dosyasını yazın: openscale debug bundle-open --key k -o paket.zip <dosya.osb>")
	}
	if *keyPath == "" || *out == "" {
		return usageError("--key ve -o zorunlu")
	}
	k, err := readBundleKey(*keyPath)
	if err != nil {
		return err
	}
	sealed, err := securefile.ReadLimited(fs.Arg(0), maxSealedBundle)
	if err != nil {
		return fmt.Errorf("paket okunamadı: %w", err)
	}
	plain, err := bundlecrypt.Open(k, sealed)
	if err != nil {
		return err
	}
	f, err := createOutput(*out, *force)
	if err != nil {
		return err
	}
	if _, err := f.Write(plain); err != nil {
		_ = f.Close()
		_ = os.Remove(*out)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Paket açıldı: %s\n", *out)
	return nil
}
