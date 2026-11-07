package msg

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/openscale/openscale/internal/securefile"
)

// Store keeps messages only on this device, in owner-only files under
// dir. Received messages and the identifiers seen (replay protection) live
// in inbox.json, written only by the listener; sent messages live in
// sent.json, written only by the sender. Deleting a message keeps its
// identifier in the seen list so a replay is still refused.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Message is a stored message.
type Message struct {
	ID   string    `json:"id"`
	Peer string    `json:"peer"`
	Out  bool      `json:"out,omitempty"`
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

const (
	inboxFile    = "inbox.json"
	sentFile     = "sent.json"
	maxStored    = 500
	maxSeen      = 4096
	maxStoreFile = 4 << 20
)

// ErrDuplicate means the message was already received.
var ErrDuplicate = errors.New("mesaj zaten alındı")

type storeFile struct {
	V        int       `json:"v"`
	Messages []Message `json:"messages"`
	Seen     []string  `json:"seen,omitempty"`
}

// OpenStore returns the store under dir; the directory is created on the
// first write.
func OpenStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) load(name string) (storeFile, error) {
	var f storeFile
	data, err := securefile.ReadLimited(filepath.Join(s.dir, name), maxStoreFile)
	if errors.Is(err, fs.ErrNotExist) {
		return storeFile{V: 1}, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, err
	}
	return f, nil
}

func (s *Store) save(name string, f storeFile) error {
	f.V = 1
	if len(f.Messages) > maxStored {
		f.Messages = f.Messages[len(f.Messages)-maxStored:]
	}
	if len(f.Seen) > maxSeen {
		f.Seen = f.Seen[len(f.Seen)-maxSeen:]
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(s.dir, name), data)
}

func (m Message) valid() bool {
	return validID(m.ID) && ValidName(m.Peer) && CheckText(m.Text) == nil
}

// AddIncoming stores a received message, refusing a repeated identifier.
func (s *Store) AddIncoming(m Message) error {
	if !m.valid() || m.Out {
		return ErrBadEnvelope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load(inboxFile)
	if err != nil {
		return err
	}
	if slices.Contains(f.Seen, m.ID) {
		return ErrDuplicate
	}
	f.Seen = append(f.Seen, m.ID)
	f.Messages = append(f.Messages, m)
	return s.save(inboxFile, f)
}

// AddSent records a message this device sent.
func (s *Store) AddSent(m Message) error {
	m.Out = true
	if !m.valid() {
		return ErrBadEnvelope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load(sentFile)
	if err != nil {
		return err
	}
	f.Messages = append(f.Messages, m)
	return s.save(sentFile, f)
}

// List returns received and sent messages, oldest first; peer filters
// when not empty.
func (s *Store) List(peer string) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []Message
	for _, name := range []string{inboxFile, sentFile} {
		f, err := s.load(name)
		if err != nil {
			return nil, err
		}
		for _, m := range f.Messages {
			if peer == "" || m.Peer == peer {
				all = append(all, m)
			}
		}
	}
	slices.SortStableFunc(all, func(a, b Message) int { return a.At.Compare(b.At) })
	return all, nil
}

// Delete removes the message with id (its replay record stays) and
// reports whether it existed.
func (s *Store) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, name := range []string{inboxFile, sentFile} {
		f, err := s.load(name)
		if err != nil {
			return found, err
		}
		n := len(f.Messages)
		f.Messages = slices.DeleteFunc(f.Messages, func(m Message) bool { return m.ID == id })
		if len(f.Messages) != n {
			found = true
			if err := s.save(name, f); err != nil {
				return found, err
			}
		}
	}
	return found, nil
}

// Clear removes every message; replay records stay.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range []string{inboxFile, sentFile} {
		f, err := s.load(name)
		if err != nil {
			return err
		}
		f.Messages = nil
		if err := s.save(name, f); err != nil {
			return err
		}
	}
	return nil
}

// SafeText makes a peer's text safe for a terminal or log: control
// characters (terminal escape sequences) and bidirectional overrides
// (misleading reordering) become '?'; newlines and tabs stay.
func SafeText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E || r == 0x200F, r == unicode.ReplacementChar:
			return '?'
		}
		return r
	}, s)
}
