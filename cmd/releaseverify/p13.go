package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

// Independent reproduction witness (#581, ADR-0148) and signed security
// advisories (#582, ADR-0149).

func addP13Flags(fl *flag.FlagSet, o *options) {
	fl.StringVar(&o.witness, "witness", "", "bağımsız derleme tanığı (*.witness.json); -witness-key ile")
	fl.StringVar(&o.witnessKey, "witness-key", "", "tanık açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...), ayrı kanaldan")
	fl.StringVar(&o.advisories, "advisories", "", "kök imzalı güvenlik bildirimi; -installed sürümü veya doğrulanan sürüm için etkileyenleri yazar")
}

// checkP13 runs the optional witness and advisory checks after the release
// itself verified.
func checkP13(o *options, root release.PublicKey, v *release.Verified, signed []byte, stdout io.Writer) error {
	if (o.witness == "") != (o.witnessKey == "") {
		return errors.New("-witness ve -witness-key birlikte verilmeli")
	}
	if o.witness != "" {
		key, err := loadKey(o.witnessKey)
		if err != nil {
			return fmt.Errorf("tanık anahtarı: %w", err)
		}
		data, err := securefile.ReadLimited(o.witness, release.MaxWitnessSize)
		if err != nil {
			return err
		}
		w, err := release.VerifyWitness(key, data)
		if err != nil {
			return err
		}
		digest, err := release.ManifestDigest(signed)
		if err != nil {
			return err
		}
		names, err := w.Confirms(&v.Manifest, digest)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Bağımsız derleme (%s, anahtar %s, %s): %s aynı\n", w.Builder, key.Fingerprint(), w.Created.Format(time.RFC3339), strings.Join(names, ", "))
	}
	if o.advisories != "" {
		return checkAdvisories(o, root, v.Manifest.Version, stdout)
	}
	return nil
}

// checkAdvisories verifies the advisory list and lists what affects the
// installed version (-installed) or, failing that, version. It fails when
// a version is affected, so scripts can stop on it.
func checkAdvisories(o *options, root release.PublicKey, version string, stdout io.Writer) error {
	data, err := securefile.ReadLimited(o.advisories, release.MaxAdvisoriesSize)
	if err != nil {
		return err
	}
	a, err := release.VerifyAdvisories(root, data, 0)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Güvenlik bildirimi: sıra %d, %s, %d kayıt\n", a.Sequence, a.Issued.Format(time.RFC3339), len(a.Advisories))
	var versions []string
	if o.installed != "" {
		versions = append(versions, o.installed)
	}
	if version != "" && version != o.installed {
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return errors.New("hangi sürümün denetleneceği belli değil: -installed verin")
	}
	affected := false
	for _, ver := range versions {
		list, err := a.Affecting(ver)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Fprintf(stdout, "TAMAM  %s: bilinen açık yok\n", ver)
			continue
		}
		affected = true
		for _, adv := range list {
			fix := "düzeltme yok"
			if adv.Fixed != "" {
				fix = adv.Fixed + " ile düzeldi"
			}
			fmt.Fprintf(stdout, "AÇIK   %s: %s [%s] %s (%s)\n", ver, adv.ID, adv.Severity, adv.Title, fix)
		}
	}
	if affected {
		return errors.New("denetlenen sürümlerden en az birini etkileyen güvenlik bildirimi var")
	}
	return nil
}

func loadKey(s string) (release.PublicKey, error) {
	if strings.HasPrefix(s, release.PublicKeyPrefix) {
		return release.ParsePublicKey(s)
	}
	data, err := securefile.ReadLimited(s, maxKeyFile)
	if err != nil {
		return release.PublicKey{}, err
	}
	return release.ParsePublicKey(string(bytes.TrimSpace(data)))
}
