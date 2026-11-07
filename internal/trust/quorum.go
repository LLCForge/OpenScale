package trust

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Quorum backup (#4, ADR-0125): k-of-n recovery of the root key without
// Shamir secret sharing. For every k-element subset of the n holders the
// root key is sealed once (the usual Argon2id + XChaCha20-Poly1305 copy,
// ADR-0003/0011) under a passphrase that only those k holders together can
// form. Any k holders open the backup; fewer learn nothing beyond what
// guessing the missing passphrases gives. No new cryptographic primitive is
// written: only the audited sealing of every other root key copy is used,
// C(n,k) times. ADR-0011's plain copies stay the default method.
//
// Unlike Shamir shares, every holder keeps the whole backup file next to
// their own passphrase; the file alone is an offline guessing target, as
// every sealed copy is.

const (
	quorumFormat = "openscale-quorum-backup-v1"
	quorumDomain = "openscale/quorum-backup/v1\x00"

	// MaxQuorumHolders bounds n.
	MaxQuorumHolders = 6
	// MaxQuorumCopies bounds C(n,k), and with it the Argon2id work of
	// creating the backup.
	MaxQuorumCopies = 20
	// MaxQuorumBackupSize bounds the encoded backup.
	MaxQuorumBackupSize = 64 << 10
)

// ErrQuorumNotMet is returned when fewer than k holders' passphrases open
// the backup.
var ErrQuorumNotMet = errors.New("not enough holders to open the quorum backup")

// QuorumBackup is the on-disk k-of-n backup.
type QuorumBackup struct {
	Format    string       `json:"format"`
	PublicKey Key          `json:"public_key"`
	Threshold int          `json:"threshold"`
	Holders   []string     `json:"holders"`
	Copies    []QuorumCopy `json:"copies"`
}

// QuorumCopy is the root key sealed for one subset of holders (indices into
// Holders, ascending).
type QuorumCopy struct {
	Members []int         `json:"members"`
	Sealed  SealedRootKey `json:"sealed"`
}

// SealQuorum seals priv for every threshold-sized subset of holders.
// passphrases[i] belongs to holders[i] and must meet the passphrase policy.
func SealQuorum(priv ed25519.PrivateKey, holders []string, passphrases [][]byte, threshold int, params Argon2Params, random io.Reader) (*QuorumBackup, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid root private key")
	}
	if len(holders) != len(passphrases) {
		return nil, errors.New("one passphrase per holder is required")
	}
	if err := checkQuorumShape(holders, threshold); err != nil {
		return nil, err
	}
	for i, p := range passphrases {
		if err := CheckPassphrase(p); err != nil {
			return nil, fmt.Errorf("holder %q: %w", holders[i], err)
		}
		for j := range i {
			if subtle.ConstantTimeCompare(p, passphrases[j]) == 1 {
				return nil, fmt.Errorf("holders %q and %q have the same passphrase", holders[j], holders[i])
			}
		}
	}
	pub, err := keyFromSlice(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	qb := &QuorumBackup{Format: quorumFormat, PublicKey: pub, Threshold: threshold, Holders: slices.Clone(holders)}
	for _, members := range subsets(len(holders), threshold) {
		combined := quorumPassphrase(members, passphrases)
		sealed, err := SealRootKey(priv, combined, params, random)
		wipe(combined)
		if err != nil {
			return nil, err
		}
		qb.Copies = append(qb.Copies, QuorumCopy{Members: members, Sealed: *sealed})
	}
	return qb, nil
}

// OpenQuorum opens the backup with the passphrases of at least Threshold
// holders, keyed by holder index. Only the first matching copy is tried,
// so a wrong passphrase is reported as ErrWrongPassphrase.
func (qb *QuorumBackup) OpenQuorum(passphrases map[int][]byte) (ed25519.PrivateKey, error) {
	if err := qb.validate(); err != nil {
		return nil, err
	}
	have := make([]int, 0, len(passphrases))
	for i := range passphrases {
		if i < 0 || i >= len(qb.Holders) {
			return nil, fmt.Errorf("unknown holder %d", i)
		}
		have = append(have, i)
	}
	slices.Sort(have)
	if len(have) < qb.Threshold {
		return nil, ErrQuorumNotMet
	}
	byIndex := make([][]byte, len(qb.Holders))
	for i, p := range passphrases {
		byIndex[i] = p
	}
	for _, c := range qb.Copies {
		if !isSubset(c.Members, have) {
			continue
		}
		combined := quorumPassphrase(c.Members, byIndex)
		defer wipe(combined)
		return c.Sealed.Open(combined)
	}
	return nil, ErrQuorumNotMet
}

// RootPublicKey returns the backed-up root public key.
func (qb *QuorumBackup) RootPublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(append([]byte(nil), qb.PublicKey[:]...))
}

// MarshalQuorumBackup encodes qb as JSON.
func MarshalQuorumBackup(qb *QuorumBackup) ([]byte, error) {
	data, err := json.MarshalIndent(qb, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode quorum backup: %w", err)
	}
	return append(data, '\n'), nil
}

// UnmarshalQuorumBackup strictly decodes and validates a quorum backup.
func UnmarshalQuorumBackup(data []byte) (*QuorumBackup, error) {
	if len(data) > MaxQuorumBackupSize {
		return nil, errors.New("quorum backup is too large")
	}
	var qb QuorumBackup
	if err := decodeStrict(data, &qb); err != nil {
		return nil, fmt.Errorf("decode quorum backup: %w", err)
	}
	if err := qb.validate(); err != nil {
		return nil, err
	}
	return &qb, nil
}

func (qb *QuorumBackup) validate() error {
	if qb.Format != quorumFormat {
		return fmt.Errorf("unsupported quorum backup format %q", qb.Format)
	}
	if qb.PublicKey.IsZero() {
		return errors.New("root public key is missing")
	}
	if err := checkQuorumShape(qb.Holders, qb.Threshold); err != nil {
		return err
	}
	want := subsets(len(qb.Holders), qb.Threshold)
	if len(qb.Copies) != len(want) {
		return errors.New("quorum backup does not hold one copy per subset")
	}
	for i := range qb.Copies {
		c := &qb.Copies[i]
		if !slices.Equal(c.Members, want[i]) {
			return errors.New("quorum backup copies are out of order")
		}
		if c.Sealed.PublicKey != qb.PublicKey {
			return errors.New("quorum backup copies hold different keys")
		}
		if err := c.Sealed.validate(); err != nil {
			return err
		}
	}
	return nil
}

func checkQuorumShape(holders []string, threshold int) error {
	n := len(holders)
	if n < 2 || n > MaxQuorumHolders {
		return fmt.Errorf("a quorum backup needs 2-%d holders", MaxQuorumHolders)
	}
	if threshold < 2 || threshold > n {
		return errors.New("threshold must be at least 2 and at most the number of holders")
	}
	if binomial(n, threshold) > MaxQuorumCopies {
		return fmt.Errorf("%d-of-%d needs more than %d copies", threshold, n, MaxQuorumCopies)
	}
	seen := make(map[string]bool, n)
	for _, h := range holders {
		if !isValidLabel(h) || seen[h] {
			return fmt.Errorf("holder name %q must be a distinct lowercase DNS label", h)
		}
		seen[h] = true
	}
	return nil
}

// quorumPassphrase derives the passphrase of one subset: the hex SHA-512 of
// the length-prefixed passphrases of its members in index order. Argon2id
// then runs over it as over any passphrase, so a guess still costs one full
// Argon2id evaluation.
func quorumPassphrase(members []int, passphrases [][]byte) []byte {
	h := sha512.New()
	h.Write([]byte(quorumDomain))
	var buf [8]byte
	for _, m := range members {
		binary.BigEndian.PutUint32(buf[:4], uint32(m))
		binary.BigEndian.PutUint32(buf[4:], uint32(len(passphrases[m])))
		h.Write(buf[:])
		h.Write(passphrases[m])
	}
	sum := h.Sum(nil)
	out := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(out, sum)
	wipe(sum)
	return out
}

// subsets lists the k-element subsets of 0..n-1 in lexicographic order.
func subsets(n, k int) [][]int {
	var out [][]int
	cur := make([]int, 0, k)
	var walk func(start int)
	walk = func(start int) {
		if len(cur) == k {
			out = append(out, slices.Clone(cur))
			return
		}
		for i := start; i <= n-(k-len(cur)); i++ {
			cur = append(cur, i)
			walk(i + 1)
			cur = cur[:len(cur)-1]
		}
	}
	walk(0)
	return out
}

func binomial(n, k int) int {
	r := 1
	for i := 1; i <= k; i++ {
		r = r * (n - k + i) / i
	}
	return r
}

func isSubset(sub, set []int) bool {
	for _, x := range sub {
		if !slices.Contains(set, x) {
			return false
		}
	}
	return true
}
