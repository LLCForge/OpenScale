package member

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Corrupt state recovery (#206, #197, ADR-0095).
//
// Every member keeps two copies of its current document: network.json and
// network.json.bak. Open repairs what it can without any outside help:
//   - state.json missing or unparsable: rebuilt from the newest valid local
//     copy of the document;
//   - network.json missing, unparsable or with a bad signature: replaced by
//     the backup copy when that has exactly the stored version.
//
// A damaged file is never deleted; it is moved aside as
// <name>.corrupt-<time> (at most maxQuarantined per name). Files that could
// not be read for another reason (permissions, I/O) are left alone and the
// error is returned as before, so a CLI run without rights never "repairs"
// a service directory. When no valid copy is left Open returns
// ErrNeedsDocument and Repair installs a document taken from another member
// (any member's network.json; it is not secret and its signature is
// checked against the pinned anchor).

const (
	backupDocumentFile = "network.json.bak"
	quarantineMark     = ".corrupt-"
	maxQuarantined     = 3
)

// ErrNeedsDocument is returned when no valid copy of the network document
// is left in a state directory.
var ErrNeedsDocument = errors.New("the stored network document is damaged and no valid copy is left; run 'openscale state repair --document <network.json of another device>'")

// errCorrupt marks content that was read but is not usable.
var errCorrupt = errors.New("corrupt")

// Recovered lists what Open repaired, one Turkish sentence each; empty
// when nothing was wrong.
func (s *Store) Recovered() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.notes)
}

// docCopy is one verified local copy of the document.
type docCopy struct {
	name   string
	doc    *trust.Document
	data   []byte
	digest [32]byte
}

// readDocCopy reads and verifies one document file. errCorrupt means the
// file exists but is unusable; other errors are read failures.
func (s *Store) readDocCopy(name string) (*docCopy, error) {
	data, err := securefile.ReadPrivate(filepath.Join(s.dir, name), trust.MaxEnvelopeSize)
	if err != nil {
		return nil, err
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	doc, err := trust.VerifyDocumentSignature(env, s.state.Anchor.RootKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	if doc.NetworkID != s.state.Anchor.NetworkID {
		return nil, fmt.Errorf("%w: document of another network", errCorrupt)
	}
	return &docCopy{name: name, doc: doc, data: data, digest: sha256.Sum256(env.Payload)}, nil
}

// recoverable reports whether err allows recovery: the file is missing or
// its content is damaged. Permission and I/O errors are not.
func recoverable(err error) bool {
	return errors.Is(err, errCorrupt) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, securefile.ErrTooLarge)
}

// loadState loads state.json and the document into s, repairing from the
// local copies when possible.
func (s *Store) loadState() error {
	st, stErr := s.readState()
	if stErr != nil && !recoverable(stErr) {
		return fmt.Errorf("read state: %w", stErr)
	}
	primary, pErr := s.readDocCopy(documentFile)
	if pErr != nil && !recoverable(pErr) {
		return fmt.Errorf("read document: %w", pErr)
	}
	var backup *docCopy
	var bErr error
	// Open runs often (status polling): a backup identical to the verified
	// primary is not verified a second time.
	if raw, err := securefile.ReadPrivate(filepath.Join(s.dir, backupDocumentFile), trust.MaxEnvelopeSize); err == nil && primary != nil && bytes.Equal(raw, primary.data) {
		backup = primary
	} else {
		backup, bErr = s.readDocCopy(backupDocumentFile)
		if bErr != nil && !recoverable(bErr) {
			backup = nil // an unreadable backup never blocks the primary
		}
	}

	if stErr != nil {
		// Rebuild the rollback state from the newest valid copy.
		best := primary
		if best == nil || (backup != nil && backup.doc.Version > best.doc.Version) {
			best = backup
		}
		if best == nil {
			s.quarantine(stateFile, stErr)
			s.quarantine(documentFile, pErr)
			s.quarantine(backupDocumentFile, bErr)
			return ErrNeedsDocument
		}
		s.quarantine(stateFile, stErr)
		s.state.HighestVersion, s.state.HighestDigest = best.doc.Version, best.digest
		if err := s.writeState(); err != nil {
			return fmt.Errorf("rebuild state: %w", err)
		}
		s.notes = append(s.notes, fmt.Sprintf("durum dosyası (state.json) bozuktu; belgenin sürüm %d kopyasından yeniden oluşturuldu", best.doc.Version))
		s.ensurePrimary(primary, pErr, best)
		s.doc, s.envelope = best.doc, best.data
		s.refreshBackup(backup, best)
		return nil
	}
	s.state.HighestVersion, s.state.HighestDigest = st.HighestVersion, st.digest

	if primary != nil && primary.doc.Version == st.HighestVersion {
		s.doc, s.envelope = primary.doc, primary.data
		s.refreshBackup(backup, primary)
		return nil
	}
	if primary != nil && primary.doc.Version > st.HighestVersion {
		// A crash between writing the document and the state (persist
		// writes the document first): the newer signed document wins.
		s.state.HighestVersion, s.state.HighestDigest = primary.doc.Version, primary.digest
		if err := s.writeState(); err != nil {
			return fmt.Errorf("update state: %w", err)
		}
		s.doc, s.envelope = primary.doc, primary.data
		s.refreshBackup(backup, primary)
		s.notes = append(s.notes, fmt.Sprintf("yarım kalan belge kaydı tamamlandı (sürüm %d)", primary.doc.Version))
		return nil
	}
	if primary != nil {
		// An older version than the state: never "repaired" from here,
		// since the state file is what guards against rollback.
		if backup != nil && backup.doc.Version == st.HighestVersion && backup.digest == st.digest {
			s.ensurePrimary(primary, nil, backup)
			s.doc, s.envelope = backup.doc, backup.data
			s.notes = append(s.notes, fmt.Sprintf("ağ belgesi durumdan eskiydi; yedek kopyadan (sürüm %d) geri yüklendi", backup.doc.Version))
			return nil
		}
		return errors.New("stored document does not match the stored state")
	}
	if backup != nil && backup.doc.Version == st.HighestVersion {
		s.ensurePrimary(nil, pErr, backup)
		s.doc, s.envelope = backup.doc, backup.data
		s.notes = append(s.notes, fmt.Sprintf("ağ belgesi (network.json) bozuktu; yedek kopyadan (sürüm %d) geri yüklendi", backup.doc.Version))
		return nil
	}
	s.quarantine(documentFile, pErr)
	return ErrNeedsDocument
}

// ensurePrimary rewrites network.json from good when it is damaged or
// missing, quarantining the damaged file first.
func (s *Store) ensurePrimary(primary *docCopy, pErr error, good *docCopy) {
	if primary != nil && primary.doc.Version == good.doc.Version && primary.digest == good.digest {
		return
	}
	if primary == nil {
		s.quarantine(documentFile, pErr)
	} else {
		s.quarantineFile(documentFile)
	}
	if err := diskguard.WriteCritical(s.dir, func() error {
		return securefile.Replace(filepath.Join(s.dir, documentFile), good.data)
	}); err != nil {
		s.notes = append(s.notes, "network.json yeniden yazılamadı: "+err.Error())
	}
}

// refreshBackup keeps network.json.bak equal to the current document.
func (s *Store) refreshBackup(backup, current *docCopy) {
	if backup != nil && backup.doc.Version == current.doc.Version && backup.digest == current.digest {
		return
	}
	if err := securefile.Replace(filepath.Join(s.dir, backupDocumentFile), current.data); err != nil && !diskguard.IsDiskFull(err) {
		s.notes = append(s.notes, "belge yedek kopyası yazılamadı: "+err.Error())
	}
}

type readStateResult struct {
	HighestVersion uint64
	digest         [32]byte
}

func (s *Store) readState() (readStateResult, error) {
	data, err := securefile.ReadPrivate(filepath.Join(s.dir, stateFile), maxSmallFile)
	if err != nil {
		return readStateResult{}, err
	}
	var st stateJSON
	if err := json.Unmarshal(data, &st); err != nil {
		return readStateResult{}, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	digest, err := hex.DecodeString(st.HighestDigest)
	if err != nil || len(digest) != sha256.Size || st.HighestVersion == 0 {
		return readStateResult{}, fmt.Errorf("%w: bad digest or version", errCorrupt)
	}
	var out readStateResult
	out.HighestVersion = st.HighestVersion
	copy(out.digest[:], digest)
	return out, nil
}

func (s *Store) writeState() error {
	st := stateJSON{HighestVersion: s.state.HighestVersion, HighestDigest: hex.EncodeToString(s.state.HighestDigest[:])}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return diskguard.WriteCritical(s.dir, func() error {
		return securefile.Replace(filepath.Join(s.dir, stateFile), data)
	})
}

// quarantine moves a damaged file aside; missing files and read errors
// other than corruption are left alone.
func (s *Store) quarantine(name string, readErr error) {
	if !errors.Is(readErr, errCorrupt) && !errors.Is(readErr, securefile.ErrTooLarge) {
		return
	}
	s.quarantineFile(name)
}

func (s *Store) quarantineFile(name string) {
	path := filepath.Join(s.dir, name)
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := path + quarantineMark + stamp
	if err := os.Rename(path, dst); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.notes = append(s.notes, name+" karantinaya alınamadı: "+err.Error())
		}
		return
	}
	s.notes = append(s.notes, fmt.Sprintf("bozuk %s karantinaya alındı: %s", name, filepath.Base(dst)))
	pruneQuarantine(s.dir, name)
}

// pruneQuarantine keeps the newest maxQuarantined copies of name.
func pruneQuarantine(dir, name string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var found []string
	prefix := name + quarantineMark
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && e.Type().IsRegular() {
			found = append(found, e.Name())
		}
	}
	slices.Sort(found) // the time stamp sorts chronologically
	for len(found) > maxQuarantined {
		_ = os.Remove(filepath.Join(dir, found[0]))
		found = found[1:]
	}
}

// Repair installs a document from another member into a state directory
// whose own copies are damaged. The anchor must be intact: the document is
// verified against it, and against the stored rollback state when that is
// still readable (an older document is refused).
func Repair(dir string, envData []byte, now time.Time) (*Store, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, anchorFile), maxSmallFile)
	if err != nil {
		return nil, ErrNotJoined
	}
	var a anchorJSON
	if err := json.Unmarshal(data, &a); err != nil || a.RootKey.IsZero() {
		return nil, errors.New("anchor file is corrupt; join the network again")
	}
	s := &Store{dir: dir}
	s.state.Anchor.RootKey = a.RootKey[:]
	s.state.Anchor.NetworkID = a.NetworkID
	// A rotated root comes from root.json, as in Open.
	if err := s.loadRoot(); err != nil {
		return nil, err
	}
	if st, err := s.readState(); err == nil {
		s.state.HighestVersion, s.state.HighestDigest = st.HighestVersion, st.digest
	} else if !recoverable(err) {
		return nil, fmt.Errorf("read state: %w", err)
	} else {
		s.quarantine(stateFile, err)
		s.notes = append(s.notes, "durum dosyası okunamadı; geri alma koruması verilen belgenin sürümünden yeniden başlıyor")
	}
	env, err := trust.UnmarshalEnvelope(envData)
	if err != nil {
		return nil, err
	}
	// Keep the approval policy of a still readable local copy (ADR-0121).
	if c, err := s.readDocCopy(documentFile); err == nil {
		s.state.PinApproval(c.doc)
	} else if c, err := s.readDocCopy(backupDocumentFile); err == nil {
		s.state.PinApproval(c.doc)
	}
	doc, err := s.state.Accept(env, now)
	if err != nil {
		return nil, err
	}
	canonical, err := trust.MarshalEnvelope(env)
	if err != nil {
		return nil, err
	}
	if _, err := s.readDocCopy(documentFile); err != nil {
		s.quarantine(documentFile, err)
	}
	if _, err := s.readDocCopy(backupDocumentFile); err != nil {
		s.quarantine(backupDocumentFile, err)
	}
	if err := s.persist(canonical); err != nil {
		return nil, err
	}
	s.doc, s.envelope = doc, canonical
	s.adoptLoadedRoot()
	s.notes = append(s.notes, fmt.Sprintf("ağ belgesi sürüm %d olarak yeniden kuruldu", doc.Version))
	return s, nil
}
