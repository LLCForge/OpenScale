package syncdir

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/openscale/openscale/internal/securefile"
)

// Encrypted backups (#137, ADR-0104). Everything is encrypted on the
// source before it leaves the device:
//
//   - The backup key is 32 random bytes kept only on the source
//     (securefile, owner only). It is independent of the network root key
//     and of the device key, so losing either does not lose the backups,
//     and the backups do not expose them. Export wraps it with a
//     passphrase (Argon2id + AES-256-GCM) for safekeeping elsewhere.
//   - Every file version gets its own random 32-byte key. Its content is
//     sealed in 1 MiB AES-256-GCM chunks (counter nonce; the index and a
//     final flag are authenticated, so chunks cannot be reordered, cut or
//     appended) and padded to 4 KiB, so the target learns sizes only to
//     that granularity. The object name is random.
//   - The manifest of a snapshot (paths, sizes, times, content hashes,
//     file keys, object names) is compressed and sealed with a key
//     derived from the backup key and a random salt.
//
// The target therefore sees only how many objects of roughly what size a
// device stores and when; never names, contents or the folder structure.

const (
	backupKeyHeader = "openscale-backup-key-v1"
	exportPrefix    = "OPENSCALE-YEDEK-ANAHTARI-1."
	blobMagic       = "OSBK1"
	manifestMagic   = "OSBM1"
	blobChunk       = 1 << 20
	padUnit         = 4096
	maxManifest     = int64(512) << 20
	minPassphrase   = 12

	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

var (
	// ErrBackupKey means the data cannot be opened with this key or was
	// modified.
	ErrBackupKey = errors.New("syncdir: yedek bu anahtarla açılamıyor veya değiştirilmiş")
	// ErrNoSnapshot means the target holds no snapshot of this store.
	ErrNoSnapshot = errors.New("syncdir: hedefte yedek yok")
)

// BackupKey encrypts one device's backups.
type BackupKey struct {
	k [32]byte
}

// NewBackupKey creates a random key.
func NewBackupKey() (*BackupKey, error) {
	var k BackupKey
	if _, err := rand.Read(k.k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

// Fingerprint identifies the key without revealing it.
func (k *BackupKey) Fingerprint() string {
	h := sha256.Sum256(append([]byte("openscale backup key id\x00"), k.k[:]...))
	s := hex.EncodeToString(h[:8])
	return s[:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:]
}

// Save writes the key owner-only; it never overwrites a file.
func (k *BackupKey) Save(p string) error {
	return securefile.WriteNew(p, []byte(backupKeyHeader+"\n"+hex.EncodeToString(k.k[:])+"\n"))
}

// LoadBackupKey reads a key saved with Save.
func LoadBackupKey(p string) (*BackupKey, error) {
	data, err := securefile.ReadPrivate(p, 4096)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(string(data))
	if len(f) != 2 || f[0] != backupKeyHeader {
		return nil, errors.New("syncdir: yedek anahtarı dosyası bozuk")
	}
	raw, err := hex.DecodeString(f[1])
	if err != nil || len(raw) != 32 {
		return nil, errors.New("syncdir: yedek anahtarı dosyası bozuk")
	}
	var k BackupKey
	copy(k.k[:], raw)
	return &k, nil
}

// LoadOrCreateBackupKey reads the key at p or creates it.
func LoadOrCreateBackupKey(p string) (*BackupKey, bool, error) {
	k, err := LoadBackupKey(p)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if k, err = NewBackupKey(); err != nil {
		return nil, false, err
	}
	if err := k.Save(p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			k, err = LoadBackupKey(p)
			return k, false, err
		}
		return nil, false, err
	}
	return k, true, nil
}

func exportAAD(salt []byte) []byte {
	a := append([]byte(exportPrefix), salt...)
	a = binary.BigEndian.AppendUint32(a, argonTime)
	a = binary.BigEndian.AppendUint32(a, argonMemory)
	return append(a, argonThreads)
}

// Export wraps the key with a passphrase (at least 12 characters) as one
// line of text to keep on paper or in a password manager.
func (k *BackupKey) Export(passphrase []byte) (string, error) {
	if len([]rune(string(passphrase))) < minPassphrase {
		return "", fmt.Errorf("syncdir: parola en az %d karakter olmalı", minPassphrase)
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	kek := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, 32)
	aead, err := gcm(kek)
	if err != nil {
		return "", err
	}
	raw := append(append(append([]byte(nil), salt...), nonce...), aead.Seal(nil, nonce, k.k[:], exportAAD(salt))...)
	return exportPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// ImportBackupKey opens an exported key.
func ImportBackupKey(text string, passphrase []byte) (*BackupKey, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, exportPrefix) {
		return nil, errors.New("syncdir: dışa aktarılmış yedek anahtarı değil")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, exportPrefix))
	if err != nil || len(raw) != 16+12+32+16 {
		return nil, errors.New("syncdir: dışa aktarılmış yedek anahtarı bozuk")
	}
	salt, nonce, ct := raw[:16], raw[16:28], raw[28:]
	aead, err := gcm(argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, 32))
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, exportAAD(salt))
	if err != nil {
		return nil, errors.New("syncdir: parola yanlış veya anahtar metni değiştirilmiş")
	}
	var k BackupKey
	copy(k.k[:], pt)
	return &k, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// --- sealed streams ---

func paddedLen(n int64) int64 { return max((n+padUnit-1)/padUnit, 1) * padUnit }

func chunkCount(padded int64) int64 { return (padded + blobChunk - 1) / blobChunk }

// sealedSize is the object size of a plaintext of n bytes.
func sealedSize(n int64) int64 {
	p := paddedLen(n)
	return int64(len(blobMagic)) + p + chunkCount(p)*16
}

func nonceFor(i int64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], uint64(i))
	return n[:]
}

func chunkAAD(i int64, final bool) []byte {
	a := binary.BigEndian.AppendUint64([]byte(blobMagic), uint64(i))
	if final {
		return append(a, 1)
	}
	return append(a, 0)
}

// sealStream encrypts exactly n bytes of r to w.
func sealStream(w io.Writer, key []byte, r io.Reader, n int64) error {
	aead, err := gcm(key)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(blobMagic)); err != nil {
		return err
	}
	p := paddedLen(n)
	chunks := chunkCount(p)
	buf := make([]byte, blobChunk)
	left := n
	for i := range chunks {
		size := min(int64(blobChunk), p-i*blobChunk)
		pt := buf[:size]
		real := min(left, size)
		if _, err := io.ReadFull(r, pt[:real]); err != nil {
			return fmt.Errorf("syncdir: dosya okunurken kısaldı: %w", err)
		}
		clear(pt[real:])
		left -= real
		if _, err := w.Write(aead.Seal(nil, nonceFor(i), pt, chunkAAD(i, i == chunks-1))); err != nil {
			return err
		}
	}
	return nil
}

// openStream decrypts an object holding n plaintext bytes from r to w.
func openStream(w io.Writer, key []byte, r io.Reader, n int64) error {
	aead, err := gcm(key)
	if err != nil {
		return err
	}
	magic := make([]byte, len(blobMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != blobMagic {
		return ErrBackupKey
	}
	p := paddedLen(n)
	chunks := chunkCount(p)
	buf := make([]byte, blobChunk+16)
	left := n
	for i := range chunks {
		size := min(int64(blobChunk), p-i*blobChunk)
		ct := buf[:size+16]
		if _, err := io.ReadFull(r, ct); err != nil {
			return ErrBackupKey
		}
		pt, err := aead.Open(ct[:0], nonceFor(i), ct, chunkAAD(i, i == chunks-1))
		if err != nil {
			return ErrBackupKey
		}
		real := min(left, size)
		if _, err := w.Write(pt[:real]); err != nil {
			return err
		}
		left -= real
	}
	var extra [1]byte
	if k, _ := r.Read(extra[:]); k != 0 {
		return ErrBackupKey
	}
	return nil
}

// --- manifests ---

// Manifest lists the files of one snapshot.
type Manifest struct {
	V       int            `json:"v"`
	Created time.Time      `json:"created"`
	Label   string         `json:"label,omitempty"`
	Files   []ManifestFile `json:"files"`
}

// ManifestFile is one file of a snapshot.
type ManifestFile struct {
	Path  string `json:"p"`
	Size  int64  `json:"s"`
	MTime int64  `json:"m"`
	Hash  string `json:"h"`
	Key   string `json:"k"`
	Blob  string `json:"b"`
}

func (k *BackupKey) manifestKey(salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, k.k[:], salt, "openscale backup manifest v1", 32)
}

func (k *BackupKey) sealManifest(m *Manifest) ([]byte, error) {
	js, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var z bytes.Buffer
	fw, _ := flate.NewWriter(&z, flate.BestCompression)
	if _, err := fw.Write(js); err != nil {
		return nil, err
	}
	if err := fw.Close(); err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	mk, err := k.manifestKey(salt)
	if err != nil {
		return nil, err
	}
	out := bytes.NewBuffer(append([]byte(manifestMagic), salt...))
	out.Write(binary.BigEndian.AppendUint64(nil, uint64(z.Len())))
	if err := sealStream(out, mk, &z, int64(z.Len())); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (k *BackupKey) openManifest(data []byte) (*Manifest, error) {
	hdr := len(manifestMagic) + 32 + 8
	if len(data) < hdr || string(data[:len(manifestMagic)]) != manifestMagic {
		return nil, ErrBackupKey
	}
	salt := data[len(manifestMagic) : len(manifestMagic)+32]
	n := int64(binary.BigEndian.Uint64(data[hdr-8 : hdr]))
	if n < 0 || n > maxManifest || sealedSize(n) != int64(len(data)-hdr) {
		return nil, ErrBackupKey
	}
	mk, err := k.manifestKey(salt)
	if err != nil {
		return nil, err
	}
	var z bytes.Buffer
	if err := openStream(&z, mk, bytes.NewReader(data[hdr:]), n); err != nil {
		return nil, err
	}
	js, err := io.ReadAll(io.LimitReader(flate.NewReader(&z), 4*maxManifest))
	if err != nil {
		return nil, ErrBackupKey
	}
	var m Manifest
	if err := json.Unmarshal(js, &m); err != nil || m.V != 1 {
		return nil, ErrBackupKey
	}
	seen := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		key, err := hex.DecodeString(f.Key)
		if err != nil || ValidatePath(f.Path) != nil || seen[f.Path] || f.Size < 0 || !validHash(f.Hash) || len(key) != 32 || !blobNameRE.MatchString(f.Blob) {
			return nil, ErrBackupKey
		}
		seen[f.Path] = true
	}
	return &m, nil
}

// BackupTarget is where snapshots are stored; *RemoteStore implements it.
type BackupTarget interface {
	Has(ctx context.Context, kind string, names []string) ([]bool, error)
	List(ctx context.Context, kind string) ([]string, error)
	Put(ctx context.Context, kind, name string, size int64, r io.Reader) error
	Get(ctx context.Context, kind, name string, maxSize int64, w io.Writer) (int64, error)
	Delete(ctx context.Context, kind, name string) error
}

// SnapshotTime returns the creation time encoded in a snapshot name.
func SnapshotTime(name string) (time.Time, bool) {
	if !manifestNameRE.MatchString(name) {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(name[:20], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, n).UTC(), true
}

// Snapshots lists the snapshot names on the target, oldest first.
func Snapshots(ctx context.Context, t BackupTarget) ([]string, error) {
	return t.List(ctx, KindManifest)
}

// LoadManifest downloads and opens one snapshot's manifest.
func LoadManifest(ctx context.Context, k *BackupKey, t BackupTarget, name string) (*Manifest, error) {
	var buf bytes.Buffer
	if _, err := t.Get(ctx, KindManifest, name, sealedSize(maxManifest)+64, &buf); err != nil {
		return nil, err
	}
	return k.openManifest(buf.Bytes())
}

// SnapshotResult reports a snapshot.
type SnapshotResult struct {
	Name          string
	Files         int
	Uploaded      int
	UploadedBytes int64
	Reused        int
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Snapshot backs up the folder to the target (#137). Files unchanged
// since the latest snapshot reuse its encrypted objects; everything else
// is encrypted with a new key and uploaded.
func Snapshot(ctx context.Context, f *Folder, k *BackupKey, t BackupTarget, label string) (SnapshotResult, error) {
	ix, err := f.Scan()
	if err != nil {
		return SnapshotResult{}, err
	}
	prev := map[string]ManifestFile{}
	names, err := Snapshots(ctx, t)
	if err != nil {
		return SnapshotResult{}, err
	}
	if len(names) > 0 {
		m, err := LoadManifest(ctx, k, t, names[len(names)-1])
		if err != nil {
			// A different key would start an unrelated chain; refuse.
			return SnapshotResult{}, fmt.Errorf("son yedek açılamadı: %w", err)
		}
		for _, mf := range m.Files {
			prev[mf.Path] = mf
		}
	}
	paths := make([]string, 0, len(ix))
	for p := range ix {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	// Reused objects must still exist on the target.
	var reuse []string
	for _, p := range paths {
		if pf, ok := prev[p]; ok && pf.Hash == ix[p].Hash && pf.Size == ix[p].Size {
			reuse = append(reuse, pf.Blob)
		}
	}
	have := map[string]bool{}
	if len(reuse) > 0 {
		ok, err := t.Has(ctx, KindBlob, reuse)
		if err != nil {
			return SnapshotResult{}, err
		}
		for i, b := range reuse {
			have[b] = ok[i]
		}
	}
	m := &Manifest{V: 1, Created: time.Now().UTC(), Label: label}
	var res SnapshotResult
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		e := ix[p]
		if pf, ok := prev[p]; ok && pf.Hash == e.Hash && pf.Size == e.Size && have[pf.Blob] {
			pf.MTime = e.MTime
			m.Files = append(m.Files, pf)
			res.Reused++
			continue
		}
		mf, err := uploadFile(ctx, f, t, p, e)
		if err != nil {
			return res, fmt.Errorf("yedeklenemedi: %w", err)
		}
		m.Files = append(m.Files, mf)
		res.Uploaded++
		res.UploadedBytes += mf.Size
	}
	data, err := k.sealManifest(m)
	if err != nil {
		return res, err
	}
	name := fmt.Sprintf("%020d-%s", m.Created.UnixNano(), randomHex(16))
	if err := t.Put(ctx, KindManifest, name, int64(len(data)), bytes.NewReader(data)); err != nil {
		return res, err
	}
	res.Name, res.Files = name, len(m.Files)
	return res, nil
}

type hashingReader struct {
	r io.Reader
	h interface{ Write([]byte) (int, error) }
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	_, _ = h.h.Write(p[:n])
	return n, err
}

func uploadFile(ctx context.Context, f *Folder, t BackupTarget, p string, e Entry) (ManifestFile, error) {
	src, err := f.root.Open(p)
	if err != nil {
		return ManifestFile{}, err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ManifestFile{}, errors.New("normal dosya değil")
	}
	size := info.Size()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return ManifestFile{}, err
	}
	h := sha256.New()
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(sealStream(pw, key, &hashingReader{r: src, h: h}, size))
	}()
	blob := randomHex(16)
	err = t.Put(ctx, KindBlob, blob, sealedSize(size), pr)
	_ = pr.CloseWithError(errors.New("bitti"))
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: p, Size: size, MTime: e.MTime, Hash: hex.EncodeToString(h.Sum(nil)), Key: hex.EncodeToString(key), Blob: blob}, nil
}

// Restore writes the snapshot's files into dest, which must be missing
// or empty (nothing is overwritten). Every file is checked against the
// content hash in the manifest.
func Restore(ctx context.Context, k *BackupKey, t BackupTarget, name, dest string) (int, error) {
	m, err := LoadManifest(ctx, k, t, name)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return 0, err
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	if entries, err := fs.ReadDir(root.FS(), "."); err != nil || len(entries) > 0 {
		return 0, errors.New("syncdir: geri yükleme klasörü boş olmalı")
	}
	n := 0
	for _, mf := range m.Files {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if err := restoreFile(ctx, root, t, mf); err != nil {
			return n, fmt.Errorf("%d. dosya geri yüklenemedi: %w", n+1, err)
		}
		n++
	}
	return n, nil
}

func restoreFile(ctx context.Context, root *os.Root, t BackupTarget, mf ManifestFile) error {
	if dir := path.Dir(mf.Path); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	key, _ := hex.DecodeString(mf.Key)
	w, err := root.OpenFile(mf.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = w.Close()
		if !ok {
			_ = root.Remove(mf.Path)
		}
	}()
	h := sha256.New()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := openStream(io.MultiWriter(w, h), key, pr, mf.Size)
		_ = pr.CloseWithError(errors.New("bitti"))
		done <- err
	}()
	_, gerr := t.Get(ctx, KindBlob, mf.Blob, sealedSize(mf.Size), pw)
	pw.CloseWithError(gerr)
	if err := <-done; err != nil {
		return err
	}
	if gerr != nil {
		return gerr
	}
	if hex.EncodeToString(h.Sum(nil)) != mf.Hash {
		return ErrBackupKey
	}
	if err := w.Close(); err != nil {
		return err
	}
	mt := time.Unix(0, mf.MTime)
	_ = root.Chtimes(mf.Path, mt, mt)
	ok = true
	return nil
}

// Prune keeps the newest keep snapshots and deletes older ones and every
// object no kept snapshot uses. The target must allow pruning.
func Prune(ctx context.Context, k *BackupKey, t BackupTarget, keep int) (int, int, error) {
	if keep < 1 {
		return 0, 0, errors.New("syncdir: en az bir yedek tutulmalı")
	}
	names, err := Snapshots(ctx, t)
	if err != nil {
		return 0, 0, err
	}
	if len(names) <= keep {
		return 0, 0, nil
	}
	used := map[string]bool{}
	for _, n := range names[len(names)-keep:] {
		m, err := LoadManifest(ctx, k, t, n)
		if err != nil {
			// Never delete what an unreadable snapshot might need.
			return 0, 0, err
		}
		for _, f := range m.Files {
			used[f.Blob] = true
		}
	}
	removedM := 0
	for _, n := range names[:len(names)-keep] {
		if err := t.Delete(ctx, KindManifest, n); err != nil {
			return removedM, 0, err
		}
		removedM++
	}
	blobs, err := t.List(ctx, KindBlob)
	if err != nil {
		return removedM, 0, err
	}
	removedB := 0
	for _, b := range blobs {
		if used[b] {
			continue
		}
		if err := t.Delete(ctx, KindBlob, b); err != nil {
			return removedM, removedB, err
		}
		removedB++
	}
	return removedM, removedB, nil
}
