package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"
)

// simTPM simulates the few TPM 2.0 commands used for sealing and EK
// reading. It checks the command structure the way a TPM would (sizes,
// tags, session area) and keeps sealed data in memory. The "private"
// blob is bound to the simulator's seed, like a real TPM's owner seed.
type simTPM struct {
	seed     byte
	handles  map[uint32][]byte // loaded objects: secret
	next     uint32
	nv       map[uint32][]byte
	commands []uint32
}

func newSim(seed byte) *simTPM {
	return &simTPM{seed: seed, handles: map[uint32][]byte{}, next: 0x80000000, nv: map[uint32][]byte{}}
}

func (s *simTPM) Close() error { return nil }

func rsp(tag uint16, rc uint32, body []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, tag)
	out = binary.BigEndian.AppendUint32(out, uint32(10+len(body)))
	out = binary.BigEndian.AppendUint32(out, rc)
	return append(out, body...)
}

func tpm2b(b []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...) }

func (s *simTPM) Submit(cmd []byte) ([]byte, error) {
	if len(cmd) < 10 || int(binary.BigEndian.Uint32(cmd[2:6])) != len(cmd) {
		return rsp(tagNoSessions, 0x1D5, nil), nil // TPM_RC_COMMAND_SIZE
	}
	tag := binary.BigEndian.Uint16(cmd)
	cc := binary.BigEndian.Uint32(cmd[6:10])
	s.commands = append(s.commands, cc)
	r := &reader{b: cmd[10:]}
	auth := func() bool {
		n := r.u32()
		if n != 9 || r.u32() != rsPW || r.u16() != 0 {
			return false
		}
		if len(r.b) < 1 {
			return false
		}
		r.b = r.b[1:]
		return r.u16() == 0 && r.err == nil
	}
	ok := func(body []byte) []byte { return rsp(tag, 0, body) }
	fail := rsp(tag, 0x101, nil) // TPM_RC_FAILURE
	switch cc {
	case ccCreatePrimary:
		if tag != tagSessions || r.u32() != rhOwner || !auth() {
			return fail, nil
		}
		sens := r.tpm2b()
		tmpl := r.tpm2b()
		if r.err != nil || !bytes.Equal(sens, []byte{0, 0, 0, 0}) || !bytes.Equal(tmpl, primaryTemplate()) {
			return fail, nil
		}
		h := s.next
		s.next++
		s.handles[h] = nil
		return ok(binary.BigEndian.AppendUint32(nil, h)), nil
	case ccCreate:
		parent := r.u32()
		if _, live := s.handles[parent]; tag != tagSessions || !live || !auth() {
			return fail, nil
		}
		sr := &reader{b: r.tpm2b()}
		sr.tpm2b()
		data := sr.tpm2b()
		tmpl := r.tpm2b()
		if r.err != nil || sr.err != nil || !bytes.Equal(tmpl, sealedTemplate()) {
			return fail, nil
		}
		priv := append([]byte{s.seed}, data...)
		for i := range priv[1:] {
			priv[1+i] ^= s.seed
		}
		body := binary.BigEndian.AppendUint32(nil, 0)
		body = append(body, tpm2b(priv)...)
		body = append(body, tpm2b(tmpl)...)
		return ok(body), nil
	case ccLoad:
		parent := r.u32()
		if _, live := s.handles[parent]; !live || !auth() {
			return fail, nil
		}
		priv := r.tpm2b()
		pub := r.tpm2b()
		if r.err != nil || len(priv) < 2 || priv[0] != s.seed || !bytes.Equal(pub, sealedTemplate()) {
			return rsp(tag, 0x0000098B, nil), nil // integrity failure on another TPM
		}
		data := bytes.Clone(priv[1:])
		for i := range data {
			data[i] ^= s.seed
		}
		h := s.next
		s.next++
		s.handles[h] = data
		return ok(binary.BigEndian.AppendUint32(nil, h)), nil
	case ccUnseal:
		h := r.u32()
		data, live := s.handles[h]
		if !live || data == nil || !auth() {
			return fail, nil
		}
		return ok(append(binary.BigEndian.AppendUint32(nil, 0), tpm2b(data)...)), nil
	case ccFlushContext:
		delete(s.handles, r.u32())
		return ok(nil), nil
	case ccNVReadPublic:
		idx := r.u32()
		d, ok2 := s.nv[idx]
		if !ok2 {
			return rsp(tag, 0x18B, nil), nil
		}
		pub := binary.BigEndian.AppendUint32(nil, idx)
		pub = binary.BigEndian.AppendUint16(pub, algSHA256)
		pub = binary.BigEndian.AppendUint32(pub, 0)
		pub = append(pub, tpm2b(nil)...)
		pub = binary.BigEndian.AppendUint16(pub, uint16(len(d)))
		return ok(append(tpm2b(pub), tpm2b([]byte{0, 0x0b})...)), nil
	case ccNVRead:
		ah, idx := r.u32(), r.u32()
		if ah != idx || !auth() {
			return fail, nil
		}
		size, off := int(r.u16()), int(r.u16())
		d := s.nv[idx]
		if off+size > len(d) {
			return fail, nil
		}
		return ok(append(binary.BigEndian.AppendUint32(nil, 0), tpm2b(d[off:off+size])...)), nil
	case ccGetCapability:
		return rsp(tagNoSessions, 0, append([]byte{0}, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, capTPMProperties), 1)...)), nil
	}
	return fail, nil
}

func TestTPM2SealRoundTrip(t *testing.T) {
	sim := newSim(0x5a)
	s := NewTPM2Sealer(sim)
	secret := []byte("cihaz anahtarı içeriği")
	env, err := SealEnvelope(s, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, secret) {
		t.Fatal("plaintext in envelope")
	}
	got, err := OpenEnvelope(s, env)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
	if len(sim.handles) != 0 {
		t.Fatalf("handles leaked: %v", sim.handles)
	}
	// Another TPM cannot load the blob.
	if _, err := OpenEnvelope(NewTPM2Sealer(newSim(0x33)), env); err == nil {
		t.Fatal("other TPM opened the envelope")
	}
	// Tampering with the ciphertext is detected.
	env[len(env)-1] ^= 1
	if _, err := OpenEnvelope(s, env); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestSealOnlyAllowlist(t *testing.T) {
	s := sealOnly{t: newSim(1)}
	for _, cc := range []uint32{0x00000120 /* EvictControl */, 0x00000137 /* NV_Write */, 0x00000126 /* Clear */, ccNVRead} {
		cmd := newCmd(tagNoSessions, cc).bytes()
		if _, err := s.Submit(cmd); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("command 0x%X passed", cc)
		}
	}
	ro := readEKOnly{t: newSim(1)}
	if _, err := ro.Submit(encodeCreatePrimary()); !errors.Is(err, ErrNotAllowed) {
		t.Fatal("evidence path can create keys")
	}
	// The original read-only wrapper still refuses sealing.
	if _, err := ReadOnly(newSim(1)).Submit(encodeCreatePrimary()); !errors.Is(err, ErrNotAllowed) {
		t.Fatal("read-only wrapper allows CreatePrimary")
	}
}

type failSealer struct{}

func (failSealer) Kind() string                  { return "tpm2" }
func (failSealer) Seal(b []byte) ([]byte, error) { return []byte("blob"), nil }
func (failSealer) Unseal([]byte) ([]byte, error) { return []byte("wrong"), nil }

func TestSealSelfCheck(t *testing.T) {
	if _, err := SealEnvelope(failSealer{}, []byte("x"), nil); !errors.Is(err, ErrSealCheck) {
		t.Fatalf("self check: %v", err)
	}
}

func selfSigned(t *testing.T, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ek"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment}
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func TestEvidenceAndJoinPolicy(t *testing.T) {
	root, rootKey := selfSigned(t, true, nil, nil)
	ek, _ := selfSigned(t, false, root, rootKey)
	sim := newSim(1)
	sim.nv[nvEKCertRSA] = append(bytes.Clone(ek.Raw), make([]byte, 100)...) // padded index
	e := CollectEvidence(Presence{Present: true, Version: "2.0"}, sim)
	if e.Method != MethodEKCert || !bytes.Equal(e.EKCert, ek.Raw) {
		t.Fatalf("evidence %+v", e)
	}
	for _, cc := range sim.commands {
		if !readEKCommands[cc] {
			t.Fatalf("evidence used command 0x%X", cc)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	now := time.Now()
	if v := EvaluateJoin(JoinPolicy{RequireTPM: true, RequireEKCert: true}, e, pool, now); !v.OK || v.Strength != "ek_cert" || v.EKFingerprint == "" {
		t.Fatalf("good evidence refused: %+v", v)
	}
	if v := EvaluateJoin(JoinPolicy{RequireEKCert: true}, e, nil, now); v.OK {
		t.Fatal("unverified chain accepted")
	}
	other, _ := selfSigned(t, true, nil, nil)
	op := x509.NewCertPool()
	op.AddCert(other)
	if v := EvaluateJoin(JoinPolicy{RequireEKCert: true}, e, op, now); v.OK {
		t.Fatal("foreign root accepted")
	}
	none := CollectEvidence(Presence{}, nil)
	if v := EvaluateJoin(JoinPolicy{RequireTPM: true}, none, nil, now); v.OK {
		t.Fatal("no TPM accepted")
	}
	if v := EvaluateJoin(JoinPolicy{}, none, nil, now); !v.OK {
		t.Fatal("empty policy refused")
	}
	if v := EvaluateJoin(JoinPolicy{Manufacturers: []string{"IFX"}}, Evidence{V: 1, Method: MethodPresence, TPM: true, Manufacturer: "INTC"}, nil, now); v.OK {
		t.Fatal("manufacturer filter ignored")
	}
	if (JoinPolicy{Manufacturers: []string{"TOOLONG"}}).Validate() == nil {
		t.Fatal("bad manufacturer accepted")
	}
}

func FuzzParseEnvelope(f *testing.F) {
	f.Add([]byte(envelopeMagic + "\x01\x00\x04abcd"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _, _, _ = ParseEnvelope(b)
		_, _, _ = splitBlob(b)
	})
}
