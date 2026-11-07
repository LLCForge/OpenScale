package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

// Witness and advisory commands (#581 ADR-0148, #582 ADR-0149):
//
//	releasesign witness-keygen -out witness.key -pub witness.pub
//	releasesign witness  -key witness.key -root-pub root.pub -release openscale-0.9.0.release.json \
//	                     -builder "ikinci makine" -out openscale-0.9.0.witness.json FILE...
//	releasesign advisory -root-key root.key -in advisories.src.json -out advisories.json [-prev advisories.json]

func cmdWitness(args []string, e *env) error {
	fs, pf := newFlags("witness", e)
	keyPath := fs.String("key", "", "şifreli tanık anahtarı")
	rootPub := fs.String("root-pub", "", "sürüm kök açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...)")
	relPath := fs.String("release", "", "doğrulanacak imzalı sürüm dosyası (*.release.json)")
	builder := fs.String("builder", "", "bağımsız derleme makinesinin adı")
	out := fs.String("out", "", "tanık dosyası")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *rootPub == "" || *relPath == "" || *builder == "" || *out == "" || fs.NArg() == 0 {
		return errors.New("-key, -root-pub, -release, -builder, -out ve bu makinede derlenmiş en az bir dosya gerekli")
	}
	root, err := loadPublicKey(*rootPub)
	if err != nil {
		return err
	}
	data, err := securefile.ReadLimited(*relPath, release.MaxSignedReleaseSize)
	if err != nil {
		return err
	}
	v, err := release.Verify(root, data, release.VerifyOptions{Now: e.now()})
	if err != nil {
		return fmt.Errorf("sürüm doğrulanamadı: %w", err)
	}
	digest, err := release.ManifestDigest(data)
	if err != nil {
		return err
	}
	var built []release.Artifact
	for _, p := range fs.Args() {
		a, err := hashFile(p)
		if err != nil {
			return err
		}
		built = append(built, a)
	}
	// A difference is reported before the passphrase is asked: a witness
	// never signs a build that does not match.
	w, err := release.NewWitness(v, digest, *builder, built, e.now())
	if err != nil {
		return fmt.Errorf("bağımsız derleme sürümle aynı değil, tanık imzalanmadı: %w", err)
	}
	e = withPassphraseFile(e, *pf)
	priv, err := openKey(e, *keyPath, release.RoleWitness)
	if err != nil {
		return err
	}
	defer wipe(priv)
	signed, err := release.SignWitness(priv, w)
	if err != nil {
		return err
	}
	if err := writePublic(*out, signed); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Tanık: %s (%s %s, %d dosya aynı)\n", *out, v.Manifest.Version, v.Manifest.Build, len(built))
	return nil
}

// advisorySource is the owner's hand-written input: the list without the
// fields the signature fills in.
type advisorySource struct {
	Sequence   uint64             `json:"sequence"`
	Advisories []release.Advisory `json:"advisories"`
}

func cmdAdvisory(args []string, e *env) error {
	fs, pf := newFlags("advisory", e)
	rootKey := fs.String("root-key", "", "şifreli sürüm kök anahtarı")
	in := fs.String("in", "", "bildirim kaynağı (JSON: sequence, advisories)")
	prev := fs.String("prev", "", "önceki imzalı bildirim dosyası (sıra numarası artmalı)")
	out := fs.String("out", "", "imzalı bildirim dosyası")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootKey == "" || *in == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("-root-key, -in ve -out gerekli")
	}
	src, err := securefile.ReadLimited(*in, release.MaxAdvisoriesSize)
	if err != nil {
		return err
	}
	var s advisorySource
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	e = withPassphraseFile(e, *pf)
	priv, err := openKey(e, *rootKey, release.RoleRoot)
	if err != nil {
		return err
	}
	defer wipe(priv)
	root, err := release.PublicKeyFrom(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	if *prev != "" {
		old, err := securefile.ReadLimited(*prev, release.MaxAdvisoriesSize)
		if err != nil {
			return err
		}
		p, err := release.VerifyAdvisories(root, old, 0)
		if err != nil {
			return fmt.Errorf("önceki liste: %w", err)
		}
		if s.Sequence <= p.Sequence {
			return fmt.Errorf("sıra numarası %d, önceki listeninkinden (%d) büyük olmalı", s.Sequence, p.Sequence)
		}
	}
	data, err := release.SignAdvisories(priv, release.Advisories{Sequence: s.Sequence, Advisories: s.Advisories}, e.now())
	if err != nil {
		return err
	}
	if _, err := release.VerifyAdvisories(root, data, s.Sequence); err != nil {
		return fmt.Errorf("imzalanan liste doğrulanamadı: %w", err)
	}
	if err := writePublic(*out, data); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Güvenlik bildirimi: %s (sıra %d, %d kayıt, %s)\n", *out, s.Sequence, len(s.Advisories), e.now().UTC().Format(time.RFC3339))
	return nil
}
