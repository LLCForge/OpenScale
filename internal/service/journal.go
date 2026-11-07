package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Change journal (ADR-0051, F-007, #163). Before the service or
// "openscale up" changes the system's DNS or routes it records the change
// here, and it removes the record once the change is undone. A record
// still present at the next start means the process crashed or was
// killed: the change is undone then, before the tunnel starts again.
//
// The persistent kill switch is deliberately not journaled: it must
// survive a crash and is removed only by the owner (ADR-0023). Firewall
// rules for the program are persistent by design (ADR-0014).

// JournalFile is the journal's name in the data or state directory.
const JournalFile = "changes.json"

// Kinds of journaled changes.
const (
	// JournalDNS: MagicDNS and the network's DNS settings (NRPT rules on
	// Windows, resolvectl on Linux).
	JournalDNS = "dns"
	// JournalExitClient: routes and DNS for using an exit node.
	JournalExitClient = "exit-client"
	// JournalExitNAT: forwarding and NAT rules of this device as an exit
	// node (Linux).
	JournalExitNAT = "exit-nat"
	// JournalMDNS: host name announcements (avahi, resolved per-link mDNS)
	// turned off for one run while the owner hides the host name (#40).
	JournalMDNS = "mdns"
)

const (
	journalSchema  = 1
	maxJournalSize = 16 << 10
	maxJournal     = 16
	recoverTimeout = 60 * time.Second
)

// JournalEntry is one change that has not been undone yet.
type JournalEntry struct {
	Kind      string `json:"kind"`
	Interface string `json:"interface,omitempty"`
	Server    string `json:"server,omitempty"`
	Domain    string `json:"domain,omitempty"`
	// MDNS is what announced the host name before a JournalMDNS change.
	MDNS *osnet.MDNSState `json:"mdns,omitempty"`
	At   time.Time        `json:"at"`
}

type journalFile struct {
	Schema  int            `json:"schema"`
	Entries []JournalEntry `json:"entries"`
}

// Journal records changes in one directory. It is safe for concurrent use
// within a process; one process owns a directory at a time.
type Journal struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

// OpenJournal returns the journal of dir; the file is created on the
// first change.
func OpenJournal(dir string, now func() time.Time) *Journal {
	if now == nil {
		now = time.Now
	}
	return &Journal{path: filepath.Join(dir, JournalFile), now: now}
}

func (j *Journal) load() (journalFile, error) {
	var f journalFile
	data, err := securefile.ReadPrivate(j.path, maxJournalSize)
	if errors.Is(err, fs.ErrNotExist) {
		return journalFile{Schema: journalSchema}, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil || f.Schema != journalSchema || len(f.Entries) > maxJournal {
		return f, errors.New("change journal is corrupt")
	}
	return f, nil
}

func (j *Journal) save(f journalFile) error {
	if len(f.Entries) == 0 {
		if err := os.Remove(j.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(j.path, data)
}

// Begin records a change before it is made; an entry of the same kind is
// replaced.
func (j *Journal) Begin(e JournalEntry) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := j.load()
	if err != nil {
		// A corrupt journal is replaced: losing old records is better
		// than not recording the change about to be made.
		f = journalFile{Schema: journalSchema}
	}
	e.At = j.now().UTC()
	f.Entries = slices.DeleteFunc(f.Entries, func(x JournalEntry) bool { return x.Kind == e.Kind })
	f.Entries = append(f.Entries, e)
	return j.save(f)
}

// Done removes the record of a change that was undone.
func (j *Journal) Done(kind string) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := j.load()
	if err != nil {
		return j.save(journalFile{Schema: journalSchema})
	}
	n := len(f.Entries)
	f.Entries = slices.DeleteFunc(f.Entries, func(x JournalEntry) bool { return x.Kind == kind })
	if len(f.Entries) == n {
		return nil
	}
	return j.save(f)
}

// Pending lists the changes not undone yet.
func (j *Journal) Pending() ([]JournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := j.load()
	return f.Entries, err
}

// JournalUndo undoes each kind of change; a nil function leaves that kind
// in the journal (tests, systems without it).
type JournalUndo struct {
	RemoveDNS  func(ctx context.Context, c osnet.DNSConfig) error
	ExitClient func(ctx context.Context, iface string) error
	ExitNAT    func(ctx context.Context) error
	MDNS       func(ctx context.Context, s osnet.MDNSState) error
}

// SystemUndo undoes changes on this system.
var SystemUndo = JournalUndo{
	RemoveDNS:  osnet.RemoveDNS,
	ExitClient: osnet.RecoverExitClient,
	ExitNAT:    osnet.RecoverExitNAT,
	MDNS:       osnet.RestoreMDNS,
}

// Recover undoes every recorded change and returns the kinds undone. A
// change that cannot be undone stays recorded and is tried again at the
// next start; its error is returned joined with the others.
func (j *Journal) Recover(ctx context.Context, u JournalUndo, logger *slog.Logger) ([]string, error) {
	pending, err := j.Pending()
	if err != nil {
		// Nothing can be read back; start over.
		_ = j.save(journalFile{Schema: journalSchema})
		return nil, fmt.Errorf("change journal unreadable: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, recoverTimeout)
	defer cancel()
	var done []string
	var errs []error
	for _, e := range pending {
		var undo func() error
		switch e.Kind {
		case JournalDNS:
			if u.RemoveDNS != nil {
				c, err := e.dnsConfig()
				if err != nil {
					errs = append(errs, err)
					_ = j.Done(e.Kind)
					continue
				}
				undo = func() error { return u.RemoveDNS(ctx, c) }
			}
		case JournalExitClient:
			if u.ExitClient != nil {
				undo = func() error { return u.ExitClient(ctx, e.Interface) }
			}
		case JournalExitNAT:
			if u.ExitNAT != nil {
				undo = func() error { return u.ExitNAT(ctx) }
			}
		case JournalMDNS:
			if u.MDNS != nil {
				if e.MDNS == nil {
					_ = j.Done(e.Kind) // nothing was recorded, nothing to put back
					continue
				}
				state := *e.MDNS
				undo = func() error { return u.MDNS(ctx, state) }
			}
		default:
			// Written by a newer version: leave it for that version.
			continue
		}
		if undo == nil {
			continue
		}
		if err := undo(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Kind, err))
			continue
		}
		if logger != nil {
			logger.Warn("undid a change left by a crash", "kind", e.Kind, "since", e.At.Format(time.RFC3339))
		}
		done = append(done, e.Kind)
		if err := j.Done(e.Kind); err != nil {
			errs = append(errs, err)
		}
	}
	return done, errors.Join(errs...)
}

func (e JournalEntry) dnsConfig() (osnet.DNSConfig, error) {
	c := osnet.DNSConfig{Interface: e.Interface, Domain: e.Domain}
	if err := c.Server.UnmarshalText([]byte(e.Server)); err != nil {
		return c, fmt.Errorf("dns record unreadable: %w", err)
	}
	return c, nil
}

// DNSEntry is the journal record of a DNS configuration.
func DNSEntry(c osnet.DNSConfig) JournalEntry {
	return JournalEntry{Kind: JournalDNS, Interface: c.Interface, Server: c.Server.String(), Domain: c.Domain}
}

// JournaledExitRouter records the exit node routes in j while they are
// installed.
func JournaledExitRouter(j *Journal, inner node.ExitRouter) node.ExitRouter {
	if inner == nil || j == nil {
		return inner
	}
	return &journaledExitRouter{j: j, inner: inner}
}

type journaledExitRouter struct {
	j     *Journal
	inner node.ExitRouter
}

func (r *journaledExitRouter) Enable(exit trust.Device, doc *trust.Document, iface string, bind conn.Bind) error {
	if err := r.j.Begin(JournalEntry{Kind: JournalExitClient, Interface: iface}); err != nil {
		return fmt.Errorf("change journal: %w", err)
	}
	return r.inner.Enable(exit, doc, iface, bind)
}

func (r *journaledExitRouter) Disable() error {
	if err := r.inner.Disable(); err != nil {
		return err
	}
	return r.j.Done(JournalExitClient)
}
