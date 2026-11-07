package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Travel mode (#248, ADR-0129). Before crossing a border the owner moves
// the root key and every administrative file out of the network directory
// into one encrypted travel archive, which they store away from the device
// (for example on a USB stick left at home or in their own cloud folder).
// Only network.json, which devices also hold, stays behind with a marker.
// On return a backup copy of the root key (ADR-0011) and its passphrase
// open the archive and restore every file.
//
// Safety order: the backup is opened and checked against the network
// before anything is touched; the archive is written, read back and
// decrypted before the originals are removed. Removal is best effort on
// SSDs and copy-on-write file systems (a forensic copy may still find
// blocks); the files are overwritten before deletion where possible.

const (
	travelFormat     = "openscale-travel-v1"
	travelMarkerFile = "travel.json"
	travelKeyInfo    = "openscale/travel-archive/v1"
	maxTravelFiles   = 100000
	// MaxTravelArchive bounds the archive (history of a large network).
	MaxTravelArchive = 256 << 20
)

// Travel errors.
var (
	ErrTraveling       = errors.New("the network directory is in travel mode; restore it first")
	ErrNotTraveling    = errors.New("the network directory is not in travel mode")
	ErrArchiveMismatch = errors.New("the travel archive does not belong to this network directory")
)

type travelArchive struct {
	Format          string `json:"format"`
	RootFingerprint string `json:"root_fingerprint"`
	Salt            []byte `json:"salt"`
	Nonce           []byte `json:"nonce"`
	Ciphertext      []byte `json:"ciphertext"`
}

type travelMarker struct {
	Format          string    `json:"format"`
	RootFingerprint string    `json:"root_fingerprint"`
	ArchiveSHA256   string    `json:"archive_sha256"`
	Files           int       `json:"files"`
	Since           time.Time `json:"since"`
}

// TravelReport says what PrepareTravel or ReturnFromTravel did.
type TravelReport struct {
	Files         int
	ArchiveSHA256 string
}

// PrepareTravel archives and removes the administrative files of dir. The
// archive is written to archivePath (which must not exist and must lie
// outside dir). backup and backupPassphrase must open a copy of the
// network's root key: this proves the owner can come back.
func PrepareTravel(dir string, backup, backupPassphrase []byte, archivePath string, random io.Reader, now time.Time) (TravelReport, error) {
	if _, err := os.Stat(filepath.Join(dir, travelMarkerFile)); err == nil {
		return TravelReport{}, ErrTraveling
	}
	if inside(dir, archivePath) {
		return TravelReport{}, errors.New("the travel archive must be stored outside the network directory")
	}
	sealed, err := readSealed(filepath.Join(dir, rootKeyFile))
	if err != nil {
		return TravelReport{}, err
	}
	backupKey, err := trust.UnmarshalSealedRootKey(backup)
	if err != nil {
		return TravelReport{}, err
	}
	if subtle.ConstantTimeCompare(backupKey.PublicKey[:], sealed.PublicKey[:]) != 1 {
		return TravelReport{}, ErrBackupKeyMismatch
	}
	if _, err := readDocument(filepath.Join(dir, documentFile), sealed.RootPublicKey()); err != nil {
		return TravelReport{}, err
	}
	rootPriv, err := backupKey.Open(backupPassphrase)
	if err != nil {
		return TravelReport{}, err
	}
	defer wipe(rootPriv)

	files, err := collectTravelFiles(dir)
	if err != nil {
		return TravelReport{}, err
	}
	plain, err := json.Marshal(files)
	if err != nil {
		return TravelReport{}, err
	}
	defer wipe(plain)
	archive, err := sealTravel(rootPriv, sealed.Fingerprint(), plain, random)
	if err != nil {
		return TravelReport{}, err
	}
	if len(archive) > MaxTravelArchive {
		return TravelReport{}, errors.New("travel archive would be too large")
	}
	if err := securefile.WriteNew(archivePath, archive); err != nil {
		return TravelReport{}, fmt.Errorf("write travel archive: %w", err)
	}
	// Read back and decrypt before removing anything.
	written, err := os.ReadFile(archivePath)
	if err != nil {
		return TravelReport{}, fmt.Errorf("read travel archive back: %w", err)
	}
	check, err := openTravel(rootPriv, sealed.Fingerprint(), written)
	if err != nil || !bytes.Equal(check, plain) {
		return TravelReport{}, errors.New("travel archive did not read back intact; nothing was removed")
	}
	wipe(check)
	sum := sha256.Sum256(written)
	marker := travelMarker{Format: travelFormat, RootFingerprint: sealed.Fingerprint(), ArchiveSHA256: hex.EncodeToString(sum[:]), Files: len(files), Since: now.UTC()}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return TravelReport{}, err
	}
	if err := securefile.WriteNew(filepath.Join(dir, travelMarkerFile), append(data, '\n')); err != nil {
		return TravelReport{}, fmt.Errorf("write travel marker: %w", err)
	}
	// root.key goes last, so an interruption leaves the key in place.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		return boolCmp(a == rootKeyFile, b == rootKeyFile)
	})
	for _, name := range names {
		if err := scrubRemove(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			return TravelReport{}, fmt.Errorf("remove %s: %w", name, err)
		}
	}
	_ = os.Remove(filepath.Join(dir, historyDir))
	return TravelReport{Files: len(files), ArchiveSHA256: marker.ArchiveSHA256}, nil
}

// ReturnFromTravel restores the files of a travel archive into dir. backup
// and backupPassphrase open the root key, which also unlocks the archive.
func ReturnFromTravel(dir string, backup, backupPassphrase, archive []byte) (TravelReport, error) {
	markerData, err := securefile.ReadPrivate(filepath.Join(dir, travelMarkerFile), 4096)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return TravelReport{}, ErrNotTraveling
		}
		return TravelReport{}, err
	}
	var marker travelMarker
	if err := json.Unmarshal(markerData, &marker); err != nil || marker.Format != travelFormat {
		return TravelReport{}, errors.New("travel marker is corrupt")
	}
	sum := sha256.Sum256(archive)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(marker.ArchiveSHA256)) != 1 {
		return TravelReport{}, ErrArchiveMismatch
	}
	backupKey, err := trust.UnmarshalSealedRootKey(backup)
	if err != nil {
		return TravelReport{}, err
	}
	if backupKey.Fingerprint() != marker.RootFingerprint {
		return TravelReport{}, ErrBackupKeyMismatch
	}
	if _, err := readDocument(filepath.Join(dir, documentFile), backupKey.RootPublicKey()); err != nil {
		return TravelReport{}, err
	}
	rootPriv, err := backupKey.Open(backupPassphrase)
	if err != nil {
		return TravelReport{}, err
	}
	defer wipe(rootPriv)
	plain, err := openTravel(rootPriv, marker.RootFingerprint, archive)
	if err != nil {
		return TravelReport{}, err
	}
	defer wipe(plain)
	var files map[string][]byte
	if err := json.Unmarshal(plain, &files); err != nil {
		return TravelReport{}, errors.New("travel archive content is corrupt")
	}
	// Validate every name before writing any file.
	for name := range files {
		if !validTravelName(name) || name == documentFile || name == travelMarkerFile {
			return TravelReport{}, fmt.Errorf("travel archive holds an invalid file name %q", name)
		}
	}
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return TravelReport{}, err
		}
		if err := securefile.Replace(path, data); err != nil {
			return TravelReport{}, fmt.Errorf("restore %s: %w", name, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, travelMarkerFile)); err != nil {
		return TravelReport{}, err
	}
	return TravelReport{Files: len(files), ArchiveSHA256: marker.ArchiveSHA256}, nil
}

// Traveling reports whether dir is in travel mode.
func Traveling(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, travelMarkerFile))
	return err == nil
}

// collectTravelFiles reads every regular file under dir except network.json.
// Anything that is not a regular file or directory stops the operation.
func collectTravelFiles(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	total := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unexpected non-regular file %s in the network directory", name)
		}
		if name == documentFile {
			return nil
		}
		if len(files) >= maxTravelFiles {
			return errors.New("too many files in the network directory")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		total += len(data)
		if total > MaxTravelArchive/2 {
			return errors.New("network directory is too large for a travel archive")
		}
		files[name] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := files[rootKeyFile]; !ok {
		return nil, errors.New("root.key is missing from the network directory")
	}
	return files, nil
}

func travelKey(rootPriv ed25519.PrivateKey, salt []byte) ([]byte, error) {
	seed := rootPriv.Seed()
	defer wipe(seed)
	return hkdf.Key(sha256.New, seed, salt, travelKeyInfo, chacha20poly1305.KeySize)
}

func sealTravel(rootPriv ed25519.PrivateKey, fingerprint string, plain []byte, random io.Reader) ([]byte, error) {
	a := travelArchive{Format: travelFormat, RootFingerprint: fingerprint, Salt: make([]byte, 32), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	if _, err := io.ReadFull(random, a.Salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(random, a.Nonce); err != nil {
		return nil, err
	}
	key, err := travelKey(rootPriv, a.Salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	a.Ciphertext = aead.Seal(nil, a.Nonce, plain, travelAD(a))
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func openTravel(rootPriv ed25519.PrivateKey, fingerprint string, data []byte) ([]byte, error) {
	if len(data) > MaxTravelArchive {
		return nil, errors.New("travel archive is too large")
	}
	var a travelArchive
	if err := json.Unmarshal(data, &a); err != nil || a.Format != travelFormat || len(a.Salt) != 32 || len(a.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("not a travel archive")
	}
	if a.RootFingerprint != fingerprint {
		return nil, ErrArchiveMismatch
	}
	key, err := travelKey(rootPriv, a.Salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, a.Nonce, a.Ciphertext, travelAD(a))
	if err != nil {
		return nil, ErrArchiveMismatch
	}
	return plain, nil
}

func travelAD(a travelArchive) []byte {
	ad := []byte(a.Format + "\x00" + a.RootFingerprint + "\x00")
	return append(ad, a.Salt...)
}

// scrubRemove overwrites a file with zeros (best effort) and removes it.
func scrubRemove(path string) error {
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		if st, err := f.Stat(); err == nil && st.Size() > 0 && st.Size() < 64<<20 {
			_, _ = f.Write(make([]byte, st.Size()))
			_ = f.Sync()
		}
		_ = f.Close()
	}
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func validTravelName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, ":") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return filepath.IsLocal(filepath.FromSlash(name))
}

func inside(dir, path string) bool {
	d, err1 := filepath.Abs(dir)
	p, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return true
	}
	rel, err := filepath.Rel(d, p)
	return err == nil && filepath.IsLocal(rel)
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}
