package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Signed objects on the coordinator (ADR-0180): the sealed admin blob and
// the warrant canary. The coordinator stores them for the members and can
// neither read nor forge them: a sealed blob is ciphertext signed by the
// root or an admin device, a canary is signed by the root. The coordinator
// checks the signature only to refuse garbage and rollbacks; every reader
// verifies again against its own pinned root and document.
//
// Wire format: the stored and transferred bytes are a JSON envelope
// {"payload": <base64>, "signature": <base64>} sent in chunks of
// control.ChunkSize, like the document. Any member may upload (so a
// coordinator that restarted in RAM mode gets the objects back from the
// devices, #633), only signed objects newer than the stored one are kept.

// SignedObject is the envelope of a stored object.
type SignedObject struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Signature contexts (Ed25519ctx, RFC 8032): an object of one kind can
// never be taken for another kind or for a document.
const (
	SealedBlobContext = "openscale/sealed-admin-blob/v1"
	CanaryContext     = "openscale/warrant-canary/v1"
)

// Message types of the signed objects (control.Message.T). Old
// coordinators answer them with "unknown message type".
const (
	TypeSealedBlob    = "sblob"
	TypeSealedBlobPut = "sblobput"
	TypeCanary        = "canary"
	TypeCanaryPut     = "canaryput"
	FeatureSealedBlob = "sblob"
	FeatureCanary     = "canary"
)

const (
	// MaxSealedBlob bounds the opaque ciphertext of a sealed blob.
	MaxSealedBlob = 48 << 10
	// maxObjectEnvelope bounds an encoded envelope (base64 and fields).
	maxObjectEnvelope = 72 << 10
	// MaxBlobKinds bounds the stored sealed blob kinds.
	MaxBlobKinds = 4
	// maxObjectUploads bounds concurrent object uploads.
	maxObjectUploads = 16
	// futureSkew is how far an object's issue time may be in the future.
	futureSkew = 5 * time.Minute
)

var blobKindRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidBlobKind reports whether kind may name a sealed blob slot.
func ValidBlobKind(kind string) bool { return blobKindRE.MatchString(kind) }

// EncodeSignedObject encodes an envelope.
func EncodeSignedObject(o SignedObject) ([]byte, error) {
	data, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	if len(data) > maxObjectEnvelope {
		return nil, errors.New("signed object too large")
	}
	return data, nil
}

// DecodeSignedObject strictly decodes an envelope.
func DecodeSignedObject(data []byte) (SignedObject, error) {
	if len(data) > maxObjectEnvelope {
		return SignedObject{}, errors.New("signed object too large")
	}
	var o SignedObject
	if err := strictJSON(data, &o); err != nil {
		return SignedObject{}, fmt.Errorf("signed object: %w", err)
	}
	if len(o.Signature) != ed25519.SignatureSize || len(o.Payload) == 0 {
		return SignedObject{}, errors.New("signed object: bad signature or empty payload")
	}
	return o, nil
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// signObject signs payload with priv under context.
func signObject(priv ed25519.PrivateKey, context string, payload []byte) (SignedObject, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedObject{}, errors.New("invalid signing key")
	}
	sig, err := priv.Sign(nil, payload, &ed25519.Options{Context: context})
	if err != nil {
		return SignedObject{}, err
	}
	return SignedObject{Payload: payload, Signature: sig}, nil
}

func verifyObject(pub trust.Key, context string, o SignedObject) error {
	if ed25519.VerifyWithOptions(ed25519.PublicKey(pub[:]), o.Payload, o.Signature, &ed25519.Options{Context: context}) != nil {
		return errors.New("signature does not verify")
	}
	return nil
}

// objectPolicy checks an uploaded envelope against the current document and
// root, and returns its sequence number.
type objectPolicy func(data []byte, doc *trust.Document, root ed25519.PublicKey, now time.Time) (seq uint64, err error)

// storedObject is one verified object.
type storedObject struct {
	seq    uint64
	data   []byte
	digest string
}

type objectUpload struct {
	slot    string
	total   int
	digest  string
	data    []byte
	updated time.Time
}

// objectStore keeps the verified objects by slot ("canary", "blob:<kind>").
type objectStore struct {
	mu      sync.Mutex
	dir     string // "" keeps objects in memory only
	objects map[string]storedObject
	uploads map[netip.Addr]*objectUpload
}

func newObjectStore(dir string) *objectStore {
	return &objectStore{dir: dir, objects: map[string]storedObject{}, uploads: map[netip.Addr]*objectUpload{}}
}

// fileFor maps a slot to its file in the state directory.
func objectFile(slot string) string {
	if slot == "canary" {
		return "warrant-canary.json"
	}
	return "sealed-" + slot[len("blob:"):] + ".json"
}

// load reads the stored objects again and keeps the ones that still pass
// their policy (a root change or a removed admin drops them).
func (st *objectStore) load(slot string, pol objectPolicy, doc *trust.Document, root ed25519.PublicKey, now time.Time) error {
	if st.dir == "" {
		return nil
	}
	data, err := securefile.ReadLimited(filepath.Join(st.dir, objectFile(slot)), maxObjectEnvelope)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Stored objects are checked like uploads, but an expired canary is
	// kept: devices must see that it was not renewed.
	seq, err := pol(data, doc, root, time.Time{})
	if err != nil {
		return fmt.Errorf("%s: %w", objectFile(slot), err)
	}
	sum := sha256.Sum256(data)
	st.mu.Lock()
	st.objects[slot] = storedObject{seq: seq, data: data, digest: hex.EncodeToString(sum[:])}
	st.mu.Unlock()
	_ = now
	return nil
}

// loadBlobs reads every sealed blob file of the state directory.
func (st *objectStore) loadBlobs(doc *trust.Document, root ed25519.PublicKey, now time.Time) []error {
	if st.dir == "" {
		return nil
	}
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		return []error{err}
	}
	var errs []error
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || len(name) < len("sealed-.json") || name[:7] != "sealed-" || filepath.Ext(name) != ".json" {
			continue
		}
		kind := name[7 : len(name)-5]
		if !ValidBlobKind(kind) || n >= MaxBlobKinds {
			continue
		}
		n++
		if err := st.load("blob:"+kind, sealedBlobPolicy(kind), doc, root, now); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// read answers one chunk of a stored object. Digest, when given on a later
// chunk, must still match, so a reader never mixes two versions.
func (st *objectStore) read(t, slot string, req control.Message) control.Message {
	st.mu.Lock()
	o, ok := st.objects[slot]
	st.mu.Unlock()
	resp := control.Message{T: t, Target: req.Target}
	if !ok {
		resp.Complete = true
		return resp
	}
	if req.Offset > 0 && req.Digest != "" && req.Digest != o.digest {
		return control.Message{T: control.TypeError, Error: "version changed"}
	}
	if req.Offset > len(o.data) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	end := min(req.Offset+control.ChunkSize, len(o.data))
	resp.Version, resp.Digest, resp.Total, resp.Offset, resp.Data = o.seq, o.digest, len(o.data), req.Offset, o.data[req.Offset:end]
	resp.Complete = end == len(o.data)
	return resp
}

// put receives one chunk of an upload, like Server.put, and stores the
// object once it is complete and passes pol.
func (st *objectStore) put(t, slot string, req control.Message, src netip.Addr, pol objectPolicy, doc *trust.Document, root ed25519.PublicKey, now time.Time) (control.Message, bool) {
	st.mu.Lock()
	if req.Offset == 0 {
		if req.Total <= 0 || req.Total > maxObjectEnvelope || len(req.Digest) != sha256.Size*2 {
			st.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "invalid upload"}, false
		}
		if _, exists := st.uploads[src]; !exists && len(st.uploads) >= maxObjectUploads {
			st.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "busy"}, false
		}
		st.uploads[src] = &objectUpload{slot: slot, total: req.Total, digest: req.Digest, data: make([]byte, 0, req.Total)}
	}
	up, ok := st.uploads[src]
	if !ok || up.slot != slot || req.Total != up.total || req.Digest != up.digest {
		st.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "no matching upload"}, false
	}
	switch {
	case req.Offset == len(up.data):
		if len(up.data)+len(req.Data) > up.total {
			delete(st.uploads, src)
			st.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "upload too long"}, false
		}
		up.data = append(up.data, req.Data...)
	case req.Offset+len(req.Data) == len(up.data):
		// Retransmission of the last chunk.
	default:
		delete(st.uploads, src)
		st.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "out of order"}, false
	}
	up.updated = now
	if len(up.data) < up.total {
		st.mu.Unlock()
		return control.Message{T: t, Offset: len(up.data)}, false
	}
	data := up.data
	delete(st.uploads, src)
	st.mu.Unlock()

	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if digest != req.Digest {
		return control.Message{T: control.TypeError, Error: "digest mismatch"}, false
	}
	seq, err := pol(data, doc, root, now)
	if err != nil {
		return control.Message{T: control.TypeError, Error: "object rejected"}, false
	}
	st.mu.Lock()
	cur, have := st.objects[slot]
	if have && cur.digest == digest {
		st.mu.Unlock()
		return control.Message{T: t, Offset: len(data), Complete: true, Version: seq}, false
	}
	if have && seq <= cur.seq {
		st.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "older than stored"}, false
	}
	if !have && slot != "canary" && st.blobCountLocked() >= MaxBlobKinds {
		st.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "too many kinds"}, false
	}
	if st.dir != "" {
		if err := securefile.Replace(filepath.Join(st.dir, objectFile(slot)), data); err != nil {
			st.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "store failed"}, false
		}
	}
	st.objects[slot] = storedObject{seq: seq, data: data, digest: digest}
	st.mu.Unlock()
	return control.Message{T: t, Offset: len(data), Complete: true, Version: seq}, true
}

func (st *objectStore) blobCountLocked() int {
	n := 0
	for slot := range st.objects {
		if slot != "canary" {
			n++
		}
	}
	return n
}

// prune drops idle uploads.
func (st *objectStore) prune(now time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for src, up := range st.uploads {
		if now.Sub(up.updated) > uploadIdleTimeout {
			delete(st.uploads, src)
		}
	}
}

// has reports the stored sequence of slot.
func (st *objectStore) has(slot string) (uint64, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	o, ok := st.objects[slot]
	return o.seq, ok
}
