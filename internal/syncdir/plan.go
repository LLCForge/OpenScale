package syncdir

import (
	"path"
	"slices"
	"strings"
)

// ActionKind is what a pull does with one path.
type ActionKind int

// Actions.
const (
	// ActFetch downloads the remote version into Path, replacing the local
	// one (which goes to the version store).
	ActFetch ActionKind = iota + 1
	// ActDelete moves the local file into the version store (the peer
	// deleted it and deletions are propagated).
	ActDelete
	// ActConflictKeepLocal keeps the local file and downloads the remote
	// version as ConflictPath.
	ActConflictKeepLocal
	// ActConflictTakeRemote moves the local file to ConflictPath and
	// downloads the remote version into Path.
	ActConflictTakeRemote
)

// Action is one planned change.
type Action struct {
	Kind         ActionKind
	Path         string
	Local        *Entry // nil when absent locally
	Remote       Entry
	ConflictPath string
}

// PlanOptions changes the plan.
type PlanOptions struct {
	// PropagateDeletes deletes local files the peer deleted.
	PropagateDeletes bool
	// MaxFileSize skips larger remote files.
	MaxFileSize int64
}

// Skipped describes a remote path the plan ignores.
type Skipped struct {
	Path   string
	Reason string
}

func same(a, b *Entry) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Hash == b.Hash
}

func lookup(ix Index, p string) *Entry {
	if e, ok := ix[p]; ok {
		return &e
	}
	return nil
}

// Plan compares the local and remote indexes with base, the state both
// devices last agreed on, and returns the actions that bring the local
// folder up to date. It is a pure function; the same inputs on both
// devices pick the same conflict winner (the later modification time,
// then the larger hash), so both converge to the same files.
func Plan(mode FolderMode, local, remote, base Index, opts PlanOptions) ([]Action, []Skipped) {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	paths := make([]string, 0, len(local)+len(remote))
	for p := range local {
		paths = append(paths, p)
	}
	for p := range remote {
		if _, ok := local[p]; !ok {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	// Paths that differ only in letter case cannot both exist on Windows
	// and macOS; the first one (local first) wins and the others are
	// skipped everywhere.
	folded := make(map[string]string, len(paths))
	for p := range local {
		folded[strings.ToLower(p)] = p
	}
	var acts []Action
	var skipped []Skipped
	for _, p := range paths {
		l, r, b := lookup(local, p), lookup(remote, p), lookup(base, p)
		if r != nil {
			if q, ok := folded[strings.ToLower(p)]; ok && q != p {
				skipped = append(skipped, Skipped{p, "yalnızca büyük/küçük harfle ayrılan başka bir dosya var"})
				continue
			}
			folded[strings.ToLower(p)] = p
			if r.Size > opts.MaxFileSize {
				skipped = append(skipped, Skipped{p, "dosya boyut sınırını aşıyor"})
				continue
			}
		}
		if same(l, r) {
			continue
		}
		switch {
		case r == nil:
			// The peer does not have it: new here, deleted there, or
			// changed here and deleted there (the change wins).
			if l != nil && b != nil && same(l, b) && opts.PropagateDeletes && mode != SendOnly {
				acts = append(acts, Action{Kind: ActDelete, Path: p, Local: l})
			}
		case l == nil:
			// Deleted here (kept deleted unless the peer changed it again
			// or the folder mirrors the peer) or new there.
			if b == nil || !same(r, b) || mode == ReceiveOnly {
				acts = append(acts, Action{Kind: ActFetch, Path: p, Remote: *r})
			}
		case mode == ReceiveOnly || (b != nil && same(l, b)):
			acts = append(acts, Action{Kind: ActFetch, Path: p, Local: l, Remote: *r})
		case b != nil && same(r, b):
			// Changed only here; the peer pulls it.
		default:
			acts = append(acts, conflict(p, l, r))
		}
	}
	return acts, skipped
}

func remoteWins(l, r *Entry) bool {
	if r.MTime != l.MTime {
		return r.MTime > l.MTime
	}
	return r.Hash > l.Hash
}

func conflict(p string, l, r *Entry) Action {
	if remoteWins(l, r) {
		return Action{Kind: ActConflictTakeRemote, Path: p, Local: l, Remote: *r, ConflictPath: ConflictName(p, l.Hash)}
	}
	return Action{Kind: ActConflictKeepLocal, Path: p, Local: l, Remote: *r, ConflictPath: ConflictName(p, r.Hash)}
}

// ConflictName names the copy of the losing version: the same on both
// devices because it depends only on the path and the loser's content.
func ConflictName(p, loserHash string) string {
	dir, file := path.Split(p)
	ext := path.Ext(file)
	if len(ext) > 16 || ext == file {
		ext = ""
	}
	stem := strings.TrimSuffix(file, ext)
	suffix := ".sync-conflict-" + loserHash[:12]
	// Keep the element within filesend's name limit.
	if over := len(stem) + len(suffix) + len(ext) - 190; over > 0 {
		cut := max(len(stem)-over, 1)
		for cut > 1 && !utf8RuneStart(stem[cut]) {
			cut--
		}
		stem = strings.TrimRight(stem[:cut], ". ")
	}
	return dir + stem + suffix + ext
}

func utf8RuneStart(b byte) bool { return b&0xc0 != 0x80 }
