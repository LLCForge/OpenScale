package privacy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Vault is an encrypted container for local secrets and documents (#660,
// ADR-0206). Overwriting a file is not dependable on SSDs and copy-on-
// write file systems: the controller may keep the old blocks. A vault
// stores every file encrypted with XChaCha20-Poly1305 under one random
// 32-byte key kept in vault.key; destroying the vault overwrites and
// removes that key first, so the remaining ciphertext is unreadable even
// where old blocks survive. The key file is small, so the chance that a
// stale copy of it survives is far lower than for whole documents; where
// a TPM is available the key can additionally be sealed (internal/tpm).
//
//	file = magic "OSVLT1\0\0" | nonce (24) | ciphertext (name is AD)
type Vault struct {
	dir string
}

const (
	vaultKeyName = "vault.key"
	vaultExt     = ".osv"
	vaultMagic   = "OSVLT1\x00\x00"
	// MaxVaultFile bounds one stored file.
	MaxVaultFile = 64 << 20
)

// Errors.
var (
	ErrVaultName      = errors.New("kasa dosya adı geçersiz")
	ErrVaultCorrupt   = errors.New("kasa dosyası doğrulanamadı")
	ErrVaultDestroyed = errors.New("kasa anahtarı yok edilmiş")
)

// OpenVault opens or creates a vault in dir (owner-only).
func OpenVault(dir string, random io.Reader) (*Vault, error) {
	if random == nil {
		random = rand.Reader
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kp := filepath.Join(dir, vaultKeyName)
	if _, err := os.Lstat(kp); errors.Is(err, fs.ErrNotExist) {
		key := make([]byte, chacha20poly1305.KeySize)
		defer clear(key)
		if _, err := io.ReadFull(random, key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(kp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, werr := f.Write(key)
		serr := f.Sync()
		cerr := f.Close()
		if err := errors.Join(werr, serr, cerr); err != nil {
			_ = os.Remove(kp)
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return &Vault{dir: dir}, nil
}

func (v *Vault) key() ([]byte, error) {
	kp := filepath.Join(v.dir, vaultKeyName)
	st, err := os.Lstat(kp)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrVaultDestroyed
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() != chacha20poly1305.KeySize {
		return nil, ErrVaultCorrupt
	}
	return os.ReadFile(kp)
}

func vaultFileName(name string) (string, error) {
	if name == "" || len(name) > 128 || name == vaultKeyName || strings.ContainsAny(name, `/\:`) ||
		strings.HasPrefix(name, ".") || filepath.Base(name) != name {
		return "", ErrVaultName
	}
	return name + vaultExt, nil
}

// Put stores data under name, replacing an earlier version atomically.
func (v *Vault) Put(name string, data []byte) error {
	fn, err := vaultFileName(name)
	if err != nil {
		return err
	}
	if len(data) > MaxVaultFile {
		return fmt.Errorf("kasa dosyası en çok %d bayt olabilir", MaxVaultFile)
	}
	key, err := v.key()
	if err != nil {
		return err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := append([]byte(vaultMagic), nonce...)
	out = aead.Seal(out, nonce, data, []byte(name))
	tmp, err := os.CreateTemp(v.dir, ".put-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(out)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(v.dir, fn))
}

// Get returns the plaintext stored under name.
func (v *Vault) Get(name string) ([]byte, error) {
	fn, err := vaultFileName(name)
	if err != nil {
		return nil, err
	}
	key, err := v.key()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	b, err := os.ReadFile(filepath.Join(v.dir, fn))
	if err != nil {
		return nil, err
	}
	hdr := len(vaultMagic) + chacha20poly1305.NonceSizeX
	if len(b) < hdr+16 || string(b[:len(vaultMagic)]) != vaultMagic {
		return nil, ErrVaultCorrupt
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	p, err := aead.Open(nil, b[len(vaultMagic):hdr], b[hdr:], []byte(name))
	if err != nil {
		return nil, ErrVaultCorrupt
	}
	return p, nil
}

// Delete removes one stored file (its ciphertext is useless without the
// key, so it is only overwritten once).
func (v *Vault) Delete(name string) error {
	fn, err := vaultFileName(name)
	if err != nil {
		return err
	}
	_, _, err = WipeFile(filepath.Join(v.dir, fn), rand.Reader)
	return err
}

// DestroyResult describes Destroy.
type DestroyResult struct {
	KeyOverwritten bool `json:"key_overwritten"`
	Files          int  `json:"files"`
}

// Destroy crypto-shreds the vault: the key is overwritten, synced and
// removed first, then every stored file and the directory are removed.
func (v *Vault) Destroy() (DestroyResult, error) {
	var res DestroyResult
	kp := filepath.Join(v.dir, vaultKeyName)
	_, over, err := WipeFile(kp, rand.Reader)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, fmt.Errorf("kasa anahtarı silinemedi: %w", err)
	}
	res.KeyOverwritten = over
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return res, err
	}
	var errs []error
	for _, e := range entries {
		p := filepath.Join(v.dir, e.Name())
		if e.Type().IsRegular() {
			if _, _, err := WipeFile(p, rand.Reader); err != nil {
				errs = append(errs, err)
				continue
			}
			res.Files++
		}
	}
	if err := errors.Join(errs...); err != nil {
		return res, err
	}
	_ = os.Remove(v.dir)
	return res, nil
}

// SecureRemove overwrites and removes a file, or every regular file below
// a directory and then the directory (#660). Symbolic links are removed,
// never followed. It is meant for received files and exported data;
// OpenScale data directories use Purge, which has more safety checks.
func SecureRemove(path string) (PurgeResult, error) {
	res := PurgeResult{Dir: path}
	st, err := os.Lstat(path)
	if err != nil {
		return res, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return res, err
	}
	if st.IsDir() && unsafeDir(abs) {
		return res, ErrUnsafePath
	}
	if !st.IsDir() {
		n, over, err := WipeFile(path, rand.Reader)
		res.Files, res.Bytes = 1, n
		if over {
			res.Overwritten = 1
		} else {
			res.NotOverwritten = append(res.NotOverwritten, filepath.Base(path))
		}
		return res, err
	}
	var dirs []string
	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
			return nil
		}
		res.Files++
		if res.Files > maxPurgeFiles {
			return ErrTooManyFiles
		}
		n, over, err := WipeFile(p, rand.Reader)
		res.Bytes += n
		if over {
			res.Overwritten++
		} else {
			rel, _ := filepath.Rel(path, p)
			res.NotOverwritten = append(res.NotOverwritten, rel)
		}
		return err
	})
	if walkErr != nil {
		return res, walkErr
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Remove(dirs[i]); err != nil {
			return res, err
		}
	}
	return res, nil
}
