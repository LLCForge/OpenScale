// Package syncdir synchronizes folders between OpenScale devices and keeps
// encrypted backups on another device (ADR-0104; #134, #135, #136, #137).
//
// Everything runs over TCP inside the tunnel. The server listens only on
// the device's tunnel address and takes the peer's identity from the
// tunnel source address, like the other OpenScale services; its Authorize
// callback answers from the owner's rules.
//
// Synchronization is pull only. A device never accepts writes into its
// folders from the network: it serves a read-only view of the folders the
// owner shared with a peer, and it changes its own folders only by
// pulling from peers it was told to follow. A read-only share (#135) is a
// folder that is served but never pulls ("send only"). Changes are
// detected by content (SHA-256), not by time stamps; a three-way
// comparison with the state both devices last agreed on decides what to
// fetch, and when both sides changed a file the newer version wins and the
// other is kept next to it as a conflict copy on both devices. Deleting is
// propagated only when enabled, and every file the synchronization
// replaces or deletes is moved into the folder's version store, where the
// last N versions are kept (#136).
//
// Backups (#137) are encrypted on the source. The target device stores
// opaque objects for each source device and never sees file names,
// contents or the key; see backup.go.
package syncdir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/filesend"
)

// DefaultPort is the tunnel TCP port of the sync and backup service.
// It equals trust.SyncPort (4050; ADR-0110 moved it from 4048, now used by
// messaging).
const DefaultPort uint16 = 4050

// MetaDir is the folder's own state directory; it is never synchronized.
const MetaDir = ".openscale-sync"

const (
	maxPathLen   = 4096
	maxPathDepth = 64
	// MaxEntries bounds the files of one folder or index.
	MaxEntries = 1_000_000
	// DefaultMaxFileSize bounds one synchronized file.
	DefaultMaxFileSize = int64(64) << 30
)

var (
	// ErrBadPath is returned for paths that cannot be stored safely.
	ErrBadPath = errors.New("syncdir: güvensiz veya taşınamaz dosya yolu")
	// ErrDenied is returned when the peer may not use a folder or store.
	ErrDenied = errors.New("syncdir: bu işlem için izin yok")
	// ErrSendOnly is returned when a send-only folder is asked to pull.
	ErrSendOnly = errors.New("syncdir: yalnızca gönderen klasör başka cihazdan değişiklik almaz")
	// ErrProtocol is returned for malformed messages.
	ErrProtocol = errors.New("syncdir: geçersiz protokol iletisi")
)

// FolderMode says in which direction a folder synchronizes.
type FolderMode string

// Folder modes.
const (
	// SendReceive serves the folder and pulls changes from peers.
	SendReceive FolderMode = "sendreceive"
	// SendOnly serves the folder and never pulls: a read-only share (#135).
	SendOnly FolderMode = "sendonly"
	// ReceiveOnly pulls and mirrors the peer; local changes are replaced
	// (the replaced versions are kept in the version store).
	ReceiveOnly FolderMode = "receiveonly"
)

// Valid reports whether m is a known mode.
func (m FolderMode) Valid() bool { return m == SendReceive || m == SendOnly || m == ReceiveOnly }

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidID reports whether s can name a folder or a backup store.
func ValidID(s string) bool { return idRE.MatchString(s) }

// ValidatePath checks a slash-separated path relative to a folder. Every
// element must be a name that every supported system stores unchanged
// (filesend.SanitizeName returns it as is), so a file name never escapes
// the folder, never becomes a device name on Windows and never hides its
// extension with bidirectional characters. Paths inside MetaDir are
// refused.
func ValidatePath(p string) error {
	if p == "" || len(p) > maxPathLen || !utf8.ValidString(p) || !fs.ValidPath(p) || p == "." ||
		strings.ContainsAny(p, "\\\x00") {
		return ErrBadPath
	}
	parts := strings.Split(p, "/")
	if len(parts) > maxPathDepth || strings.EqualFold(parts[0], MetaDir) {
		return ErrBadPath
	}
	for _, part := range parts {
		clean, err := filesend.SanitizeName(part)
		if err != nil || clean != part {
			return ErrBadPath
		}
	}
	return nil
}

// Entry describes one file.
type Entry struct {
	Size int64 `json:"s"`
	// MTime is the modification time in Unix nanoseconds. It is only used
	// to skip hashing unchanged files and to pick the newer version of a
	// conflict; changes are detected by Hash.
	MTime int64 `json:"m"`
	// Hash is the hex SHA-256 of the content.
	Hash string `json:"h"`
}

// Index maps folder-relative paths to entries.
type Index map[string]Entry

func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}

func (e Entry) valid(maxSize int64) bool {
	return e.Size >= 0 && e.Size <= maxSize && validHash(e.Hash)
}

type indexFile struct {
	V       int   `json:"v"`
	Entries Index `json:"entries"`
}

func marshalIndex(ix Index) ([]byte, error) {
	return json.Marshal(indexFile{V: 1, Entries: ix})
}

func unmarshalIndex(data []byte) (Index, error) {
	var f indexFile
	if err := json.Unmarshal(data, &f); err != nil || f.V != 1 {
		return nil, fmt.Errorf("%w: dizin dosyası", ErrProtocol)
	}
	if f.Entries == nil {
		f.Entries = Index{}
	}
	if len(f.Entries) > MaxEntries {
		return nil, fmt.Errorf("%w: çok fazla dosya", ErrProtocol)
	}
	for p, e := range f.Entries {
		if ValidatePath(p) != nil || !e.valid(1<<62) {
			return nil, fmt.Errorf("%w: geçersiz dizin girdisi", ErrProtocol)
		}
	}
	return f.Entries, nil
}
