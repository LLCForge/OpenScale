package syncdir

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// Backup integrity probe (#452, ADR-0159). The source downloads a few
// randomly chosen objects of its latest snapshot, decrypts them and
// compares their content hash with the manifest, checks that every object
// the snapshot needs is still on the target and that one older manifest
// still opens. The target sees only ordinary downloads of opaque objects;
// it learns nothing it did not know. A probe answers "can this backup be
// restored" without restoring it.

// errProbeStop ends a download the decryption no longer reads.
var errProbeStop = errors.New("syncdir: yoklama okuması bitti")

const (
	// DefaultProbeFiles is how many files a probe decrypts.
	DefaultProbeFiles = 8
	// DefaultProbeBytes bounds the plaintext a probe downloads.
	DefaultProbeBytes = int64(256) << 20
	maxProbeFiles     = 1000
	maxProbeList      = 20
)

// ProbeOptions tunes a probe.
type ProbeOptions struct {
	// Files is how many files to decrypt (default 8, at most 1000).
	Files int
	// MaxBytes bounds the plaintext size downloaded (default 256 MiB);
	// files that do not fit are not chosen.
	MaxBytes int64
	// Intn returns a uniform number in [0, n); nil uses crypto/rand.
	Intn func(n int) int
}

// ProbeProblem is one file that failed.
type ProbeProblem struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ProbeResult reports a probe. OK is true only when every check passed
// and at least one file was decrypted (or the snapshot is empty).
type ProbeResult struct {
	Snapshot     string         `json:"snapshot"`
	SnapshotTime time.Time      `json:"snapshot_time"`
	Snapshots    int            `json:"snapshots"`
	Files        int            `json:"files"`
	Checked      int            `json:"checked"`
	Bytes        int64          `json:"bytes"`
	Missing      int            `json:"missing"`
	OlderChecked string         `json:"older_checked,omitempty"`
	Problems     []ProbeProblem `json:"problems,omitempty"`
	OK           bool           `json:"ok"`
}

func cryptoIntn(n int) int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}

func (r *ProbeResult) problem(p, why string) {
	if len(r.Problems) < maxProbeList {
		r.Problems = append(r.Problems, ProbeProblem{Path: p, Reason: why})
	}
}

// Probe checks the latest snapshot on t with key k. A network or target
// error is returned as an error; damaged or missing data is reported in
// the result (OK false).
func Probe(ctx context.Context, k *BackupKey, t BackupTarget, opts ProbeOptions) (ProbeResult, error) {
	if opts.Files <= 0 {
		opts.Files = DefaultProbeFiles
	}
	opts.Files = min(opts.Files, maxProbeFiles)
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultProbeBytes
	}
	if opts.Intn == nil {
		opts.Intn = cryptoIntn
	}
	var res ProbeResult
	names, err := Snapshots(ctx, t)
	if err != nil {
		return res, err
	}
	if len(names) == 0 {
		return res, ErrNoSnapshot
	}
	res.Snapshots = len(names)
	res.Snapshot = names[len(names)-1]
	res.SnapshotTime, _ = SnapshotTime(res.Snapshot)
	m, err := LoadManifest(ctx, k, t, res.Snapshot)
	if errors.Is(err, ErrBackupKey) {
		res.problem("", "son yedeğin içerik listesi bu anahtarla açılmıyor veya değiştirilmiş")
		return res, nil
	}
	if err != nil {
		return res, err
	}
	res.Files = len(m.Files)
	// Every object the snapshot needs must exist.
	blobs := make([]string, len(m.Files))
	for i, f := range m.Files {
		blobs[i] = f.Blob
	}
	present := make([]bool, len(blobs))
	if len(blobs) > 0 {
		if present, err = t.Has(ctx, KindBlob, blobs); err != nil {
			return res, err
		}
	}
	var candidates []int
	for i, ok := range present {
		if !ok {
			res.Missing++
			res.problem(m.Files[i].Path, "şifreli parça hedefte yok")
			continue
		}
		if m.Files[i].Size <= opts.MaxBytes {
			candidates = append(candidates, i)
		}
	}
	// Random choice without replacement within the byte budget.
	budget := opts.MaxBytes
	for len(candidates) > 0 && res.Checked < opts.Files {
		j := opts.Intn(len(candidates))
		i := candidates[j]
		candidates[j] = candidates[len(candidates)-1]
		candidates = candidates[:len(candidates)-1]
		mf := m.Files[i]
		if mf.Size > budget {
			continue
		}
		budget -= mf.Size
		if err := ctx.Err(); err != nil {
			return res, err
		}
		why, err := probeFile(ctx, t, mf)
		if err != nil {
			return res, err
		}
		res.Checked++
		res.Bytes += mf.Size
		if why != "" {
			res.problem(mf.Path, why)
		}
	}
	// One older manifest must still open (a damaged chain would surface
	// only at restore time otherwise).
	if len(names) > 1 {
		older := names[opts.Intn(len(names)-1)]
		res.OlderChecked = older
		if _, err := LoadManifest(ctx, k, t, older); errors.Is(err, ErrBackupKey) {
			res.problem("", "eski bir yedeğin içerik listesi açılmıyor: "+older)
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return res, err
		}
	}
	res.OK = len(res.Problems) == 0 && res.Missing == 0 && (res.Checked > 0 || res.Files == 0)
	if res.Files > 0 && res.Checked == 0 && len(res.Problems) == 0 {
		res.problem("", fmt.Sprintf("seçilen dosyaların hiçbiri %d MiB sınırına sığmadı", opts.MaxBytes>>20))
	}
	return res, nil
}

// probeFile downloads, decrypts and hashes one file; it returns a
// non-empty reason for damaged data and an error for transport failures.
func probeFile(ctx context.Context, t BackupTarget, mf ManifestFile) (string, error) {
	key, err := hex.DecodeString(mf.Key)
	if err != nil || len(key) != 32 {
		return "içerik listesindeki anahtar bozuk", nil
	}
	h := sha256.New()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := openStream(h, key, pr, mf.Size)
		_ = pr.CloseWithError(errProbeStop)
		done <- err
	}()
	_, gerr := t.Get(ctx, KindBlob, mf.Blob, sealedSize(mf.Size), pw)
	pw.CloseWithError(gerr)
	oerr := <-done
	switch {
	case errors.Is(gerr, ErrNotFound):
		return "şifreli parça hedefte yok", nil
	case gerr != nil && !errors.Is(gerr, errProbeStop):
		// The transfer failed (network, target); not a verdict on data.
		return "", gerr
	case oerr != nil:
		return "şifreli parça açılamıyor (bozuk veya değiştirilmiş)", nil
	}
	if hex.EncodeToString(h.Sum(nil)) != mf.Hash {
		return "çözülen içerik beklenen özetle eşleşmiyor", nil
	}
	return "", nil
}
