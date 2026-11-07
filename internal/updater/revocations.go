package updater

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

// Revocation of release signing keys is not optional (ADR-0022, ADR-0195).
// The newest root-signed list this device knows is enforced on every
// verification: the update path and the start-up self check alike. A list
// comes from the program itself (EmbeddedRevocations), from the update
// folder (RevocationsFile, kept by Apply and "openscale update revocations"),
// from --revocations or from next to the manifest. The stored list is also
// the high water mark: an older list given later is refused, so an old list
// cannot bring a revoked key back.

// RevocationsFile is the signed list in the update folder and, under the
// same name, next to a release's manifest.
const RevocationsFile = "revocations.json"

const revocationsFetchTimeout = 30 * time.Second

// EmbeddedRevocations is the base64 form of the signed list current when
// this program was released, set by the release script with
// -X .../internal/updater.EmbeddedRevocations=... It applies with
// EmbeddedRootKey only.
var EmbeddedRevocations = ""

// Revocation errors.
var (
	// ErrRevocationsStale is returned for a list older than the one this
	// device already holds.
	ErrRevocationsStale = errors.New("iptal listesi bu cihazdakinden eski; eski bir liste iptal edilmiş anahtarı geri getiremez")
	// ErrRevocationsConflict is returned for two different lists that carry
	// the same sequence number.
	ErrRevocationsConflict = errors.New("aynı sıra numarasıyla iki farklı iptal listesi var")
)

// KnownRevocations returns the newest list stored in stateDir or embedded in
// the program, or nil when there is none. A list that exists but does not
// verify is an error: it never counts as no list.
func KnownRevocations(stateDir string, root release.PublicKey) (*release.Revocations, error) {
	best, err := embeddedRevocations(root)
	if err != nil {
		return nil, err
	}
	if stateDir == "" {
		return best, nil
	}
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, RevocationsFile), release.MaxRevocationsSize)
	if errors.Is(err, fs.ErrNotExist) {
		return best, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kayıtlı iptal listesi okunamadı: %w", err)
	}
	stored, err := release.VerifyRevocations(root, data)
	if err != nil {
		return nil, fmt.Errorf("kayıtlı iptal listesi doğrulanamadı: %w", err)
	}
	return newerRevocations(best, stored)
}

func embeddedRevocations(root release.PublicKey) (*release.Revocations, error) {
	if EmbeddedRevocations == "" || EmbeddedRootKey == "" {
		return nil, nil
	}
	// A list only speaks for its own root; --root-key may name another one.
	if k, err := release.ParsePublicKey(EmbeddedRootKey); err != nil || !k.Equal(root) {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(EmbeddedRevocations)
	if err != nil {
		return nil, fmt.Errorf("programa gömülü iptal listesi bozuk: %w", err)
	}
	list, err := release.VerifyRevocations(root, data)
	if err != nil {
		return nil, fmt.Errorf("programa gömülü iptal listesi doğrulanamadı: %w", err)
	}
	return list, nil
}

// newerRevocations picks the higher sequence; a tie must be the same list.
func newerRevocations(a, b *release.Revocations) (*release.Revocations, error) {
	switch {
	case a == nil:
		return b, nil
	case b == nil:
		return a, nil
	case a.Sequence > b.Sequence:
		return a, nil
	case b.Sequence > a.Sequence:
		return b, nil
	}
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	if errX != nil || errY != nil || !bytes.Equal(x, y) {
		return nil, ErrRevocationsConflict
	}
	return a, nil
}

// effectiveRevocations returns the list to enforce for opts. A list the
// caller supplied must not be older than the one already known.
func effectiveRevocations(opts Options) (*release.Revocations, error) {
	known, err := KnownRevocations(opts.StateDir, opts.Root)
	if err != nil {
		return nil, err
	}
	if opts.Revocations == nil {
		return known, nil
	}
	if !opts.Revocations.RootKey.Equal(opts.Root) {
		return nil, errors.New("iptal listesi başka bir sürüm kök anahtarına ait")
	}
	if known != nil && opts.Revocations.Sequence < known.Sequence {
		return nil, fmt.Errorf("%w (verilen %d, cihazdaki %d)", ErrRevocationsStale, opts.Revocations.Sequence, known.Sequence)
	}
	return newerRevocations(known, opts.Revocations)
}

// adoptRevocations takes the list published with src when it is newer than
// what is known, stores the newest list in the update folder and warns when
// no list exists at all. A stale list next to a manifest is only ignored: an
// old mirror is normal and the known list stays in force.
func adoptRevocations(opts *Options, src Source) error {
	if err := takePublishedRevocations(opts, src.Revocations); err != nil {
		return err
	}
	list, err := effectiveRevocations(*opts)
	if err != nil {
		return err
	}
	if list == nil {
		opts.Logf("UYARI: bu cihazda ve bu sürümde imzalı iptal listesi yok; iptal edilmiş bir imzalama anahtarı bu nedenle tanınamaz.")
		return nil
	}
	if opts.StateDir == "" {
		return nil
	}
	return storeRevocations(opts.StateDir, opts.Root, list)
}

// takePublishedRevocations makes the signed list published with a release the
// one to enforce when it is newer than what opts already has.
func takePublishedRevocations(opts *Options, published []byte) error {
	if len(published) == 0 {
		return nil
	}
	list, err := release.VerifyRevocations(opts.Root, published)
	if err != nil {
		return fmt.Errorf("sürümle gelen iptal listesi doğrulanamadı: %w", err)
	}
	known, err := KnownRevocations(opts.StateDir, opts.Root)
	if err != nil {
		return err
	}
	switch {
	case known != nil && list.Sequence < known.Sequence:
		opts.Logf("Sürümle gelen iptal listesi (sıra %d) bu cihazdakinden (sıra %d) eski; yok sayıldı.", list.Sequence, known.Sequence)
	case opts.Revocations == nil || list.Sequence > opts.Revocations.Sequence:
		opts.Revocations = list
	}
	return nil
}

// VerifySource judges src exactly as Apply would, the list published next to
// its manifest included, and changes nothing on this device. It is what
// "update apply --verify-only" runs.
func VerifySource(opts Options, src Source) (*release.Verified, error) {
	opts.defaults()
	if err := checkRoot(opts); err != nil {
		return nil, err
	}
	if err := takePublishedRevocations(&opts, src.Revocations); err != nil {
		return nil, err
	}
	return Verify(opts, src.Manifest)
}

// EnforcedRevocations returns the list a verification outside Apply must pass
// to release.Verify: the newest of the stored or embedded list, the given one
// and the one published next to the manifest. The result may be nil.
func EnforcedRevocations(stateDir string, root release.PublicKey, given *release.Revocations, published []byte, logf func(string, ...any)) (*release.Revocations, error) {
	opts := Options{Root: root, StateDir: stateDir, Revocations: given, Logf: logf}
	opts.defaults()
	if err := takePublishedRevocations(&opts, published); err != nil {
		return nil, err
	}
	return effectiveRevocations(opts)
}

// storeRevocations keeps list unless the stored one is the same or newer.
// A list without its signed form (embedded lists have one; only hand-built
// values lack it) cannot be stored.
func storeRevocations(stateDir string, root release.PublicKey, list *release.Revocations) error {
	signed := list.Signed()
	if len(signed) == 0 {
		return nil
	}
	path := filepath.Join(stateDir, RevocationsFile)
	if current, err := securefile.ReadPrivate(path, release.MaxRevocationsSize); err == nil {
		old, err := release.VerifyRevocations(root, current)
		if err != nil {
			return fmt.Errorf("kayıtlı iptal listesi doğrulanamadı: %w", err)
		}
		if old.Sequence >= list.Sequence {
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("kayıtlı iptal listesi okunamadı: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := securefile.Replace(path, signed); err != nil {
		return fmt.Errorf("iptal listesi kaydedilemedi: %w", err)
	}
	return nil
}

// InstallRevocations verifies a signed list and stores it in stateDir, so
// the next start and every later update enforce it. An older list is refused.
func InstallRevocations(stateDir string, root release.PublicKey, data []byte) (*release.Revocations, error) {
	if stateDir == "" {
		return nil, errors.New("güncelleme klasörü yok")
	}
	list, err := release.VerifyRevocations(root, data)
	if err != nil {
		return nil, fmt.Errorf("iptal listesi doğrulanamadı: %w", err)
	}
	if _, err := effectiveRevocations(Options{Root: root, StateDir: stateDir, Revocations: list}); err != nil {
		return nil, err
	}
	if err := storeRevocations(stateDir, root, list); err != nil {
		return nil, err
	}
	return list, nil
}

// fetchRevocations reads the list next to a manifest URL. It is best effort:
// a server without one, or one that fails, leaves the known list in force.
func fetchRevocations(ctx context.Context, client *http.Client, manifest *url.URL) []byte {
	base := *manifest
	base.RawQuery = ""
	i := strings.LastIndex(base.Path, "/")
	if i < 0 {
		return nil
	}
	base.Path = base.Path[:i+1] + RevocationsFile
	ctx, cancel := context.WithTimeout(ctx, revocationsFetchTimeout)
	defer cancel()
	data, err := fetch(ctx, client, base.String(), release.MaxRevocationsSize)
	if err != nil {
		return nil
	}
	return data
}
