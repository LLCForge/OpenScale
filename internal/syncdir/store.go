package syncdir

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// The backup target side (#137). Each source device gets its own tree
// under the backup directory, named by the device name the rules give it
// (never by anything the source sends):
//
//	<peer>/<store>/blobs/<2 hex>/<32 hex>   encrypted file contents
//	<peer>/<store>/manifests/<seq>-<32 hex> encrypted snapshot manifests
//
// Objects are opaque ciphertext. They are written once and never
// overwritten; deleting needs Access.AllowPrune. The target checks the
// SHA-256 trailer of every upload, so a broken transfer never leaves a
// damaged object behind.

// Object kinds.
const (
	KindBlob     = "blob"
	KindManifest = "manifest"
)

var (
	blobNameRE     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	manifestNameRE = regexp.MustCompile(`^[0-9]{20}-[0-9a-f]{32}$`)
)

func validObject(kind, name string) bool {
	switch kind {
	case KindBlob:
		return blobNameRE.MatchString(name)
	case KindManifest:
		return manifestNameRE.MatchString(name)
	}
	return false
}

func objectPath(store, kind, name string) string {
	if kind == KindBlob {
		return store + "/blobs/" + name[:2] + "/" + name
	}
	return store + "/manifests/" + name
}

type blobStore struct {
	root      *os.Root
	maxObject int64

	mu    sync.Mutex
	usage map[string]int64 // per peer, computed on first use
}

func openBlobStore(dir string, maxObject int64) (*blobStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("syncdir: yedek klasörü oluşturulamadı: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &blobStore{root: root, maxObject: maxObject, usage: map[string]int64{}}, nil
}

func (b *blobStore) peerUsage(peer string) int64 {
	if u, ok := b.usage[peer]; ok {
		return u
	}
	var total int64
	_ = fs.WalkDir(b.root.FS(), peer, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	b.usage[peer] = total
	return total
}

// reserve books n bytes of the peer's quota.
func (b *blobStore) reserve(peer string, quota, n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.peerUsage(peer)
	if quota <= 0 || u+n > quota {
		return false
	}
	b.usage[peer] = u + n
	return true
}

func (b *blobStore) release(peer string, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.usage[peer]; ok {
		b.usage[peer] -= n
	}
}

func (b *blobStore) serve(s *Server, st *connState, acc Access, req request) error {
	store := acc.Peer + "/" + req.Store
	switch req.Op {
	case opHas:
		if !validKind(req.Kind) || len(req.Names) > maxHasNames {
			return s.reply(st, response{Status: stBad})
		}
		have := make([]bool, len(req.Names))
		for i, n := range req.Names {
			if validObject(req.Kind, n) {
				_, err := b.root.Lstat(objectPath(store, req.Kind, n))
				have[i] = err == nil
			}
		}
		return s.reply(st, response{Status: stOK, Have: have})
	case opList:
		if !validKind(req.Kind) {
			return s.reply(st, response{Status: stBad})
		}
		names := b.list(store, req.Kind)
		i := sort.SearchStrings(names, req.After)
		if i < len(names) && names[i] == req.After {
			i++
		}
		end := min(i+maxListPage, len(names))
		return s.reply(st, response{Status: stOK, Names: names[i:end], More: end < len(names)})
	case opFetch:
		if !validObject(req.Kind, req.Name) {
			return s.reply(st, response{Status: stBad})
		}
		f, err := b.root.Open(objectPath(store, req.Kind, req.Name))
		if err != nil {
			return s.reply(st, response{Status: stNotFound})
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return s.reply(st, response{Status: stNotFound})
		}
		if err := s.reply(st, response{Status: stOK, Size: info.Size()}); err != nil {
			return err
		}
		_, err = io.CopyN(&deadlineWriter{c: st.c, idle: dataIdle}, f, info.Size())
		return err
	case opDel:
		if !validObject(req.Kind, req.Name) {
			return s.reply(st, response{Status: stBad})
		}
		if !acc.AllowPrune {
			return s.reply(st, response{Status: stDenied, Error: "bu yedek hedefi yalnızca ekleme kipinde"})
		}
		p := objectPath(store, req.Kind, req.Name)
		info, err := b.root.Lstat(p)
		if err != nil {
			return s.reply(st, response{Status: stNotFound})
		}
		if err := b.root.Remove(p); err != nil {
			return s.reply(st, response{Status: stError})
		}
		b.release(acc.Peer, info.Size())
		return s.reply(st, response{Status: stOK})
	case opPut:
		return b.put(s, st, acc, store, req)
	}
	return s.reply(st, response{Status: stBad})
}

func validKind(k string) bool { return k == KindBlob || k == KindManifest }

func (b *blobStore) list(store, kind string) []string {
	var names []string
	dir := store + "/manifests"
	if kind == KindBlob {
		dir = store + "/blobs"
	}
	_ = fs.WalkDir(b.root.FS(), dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && validObject(kind, path.Base(p)) {
			names = append(names, path.Base(p))
		}
		return nil
	})
	slices.Sort(names)
	return names
}

func (b *blobStore) put(s *Server, st *connState, acc Access, store string, req request) error {
	if !validObject(req.Kind, req.Name) || req.Size < 0 || req.Size > b.maxObject {
		return s.reply(st, response{Status: stBad})
	}
	dst := objectPath(store, req.Kind, req.Name)
	if _, err := b.root.Lstat(dst); err == nil {
		// Objects are never overwritten.
		return s.reply(st, response{Status: stBad, Error: "nesne zaten var"})
	}
	if !b.reserve(acc.Peer, acc.Quota, req.Size) {
		return s.reply(st, response{Status: stQuota})
	}
	ok := false
	defer func() {
		if !ok {
			b.release(acc.Peer, req.Size)
		}
	}()
	if err := b.root.MkdirAll(store+"/tmp", 0o700); err != nil {
		return s.reply(st, response{Status: stError})
	}
	if err := b.root.MkdirAll(path.Dir(dst), 0o700); err != nil {
		return s.reply(st, response{Status: stError})
	}
	tmp := store + "/tmp/" + randomName()
	f, err := b.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return s.reply(st, response{Status: stError})
	}
	defer func() {
		_ = f.Close()
		if !ok {
			_ = b.root.Remove(tmp)
		}
	}()
	if err := s.reply(st, response{Status: stReady}); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(f, h), &deadlineReader{c: st.c, r: st.br, idle: dataIdle}, req.Size); err != nil {
		return err
	}
	_ = st.c.SetReadDeadline(time.Now().Add(dataIdle))
	var trailer request
	if err := readFrame(st.br, &trailer); err != nil {
		return err
	}
	if !strings.EqualFold(trailer.SHA256, hex.EncodeToString(h.Sum(nil))) {
		return s.reply(st, response{Status: stBad, Error: "bütünlük doğrulaması başarısız"})
	}
	if err := f.Sync(); err != nil {
		return s.reply(st, response{Status: stError})
	}
	if err := f.Close(); err != nil {
		return s.reply(st, response{Status: stError})
	}
	if _, err := b.root.Lstat(dst); err == nil {
		return s.reply(st, response{Status: stBad, Error: "nesne zaten var"})
	}
	if err := b.root.Rename(tmp, dst); err != nil {
		return s.reply(st, response{Status: stError})
	}
	ok = true
	s.log.Info("yedek nesnesi alındı", "peer", acc.Peer, "kind", req.Kind, "size", req.Size)
	return s.reply(st, response{Status: stOK})
}

var errStore = errors.New("syncdir: yedek hedefi isteği reddetti")
