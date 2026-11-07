package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"
)

// Passphrases used by tests across the repository must stay valid.
var acceptedPassphrases = []string{
	"doğru at pil zımba 9", "yepyeni uzun parola 7", "yedek kopya parolası 3",
	"koordinatör uzantı testi 1", "uçtan uca test parolası 1", "panel test parolası 1",
	"servis testi parolası 42", "dogru parola 123", "çok güçlü şifre", "çok gizli parola 42",
	"ayrı bir yedek parolası 5", "tamamen yeni parola 88", "doğru at pil zımba 42",
	"x7#kQ9!mP2&z", "orman kalem deniz bulut", "kdjfuwnxbqpa",
}

var rejectedPassphrases = []string{
	"password1234", "Password1234!", "P@ssw0rd2024", "qwertyuiop12", "Galatasaray1905",
	"abcdefghijkl", "asdf1234asdf", "parola123456", "123456789012", "Şifre12345678",
	"fenerbahce1907", "istanbul2023!", "qazwsxedcrfv", "abcd1234abcd1234", "zxcvbnm12345",
}

func TestPassphraseStrength(t *testing.T) {
	for _, p := range acceptedPassphrases {
		if err := CheckPassphrase([]byte(p)); err != nil {
			t.Errorf("%q rejected (%.1f bits): %v", p, EstimatePassphraseBits([]byte(p)), err)
		}
	}
	for _, p := range rejectedPassphrases {
		err := CheckPassphrase([]byte(p))
		if !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("%q accepted (%.1f bits)", p, EstimatePassphraseBits([]byte(p)))
		}
	}
	if !errors.Is(ErrGuessablePassphrase, ErrWeakPassphrase) || !errors.Is(ErrGuessablePassphrase, ErrGuessablePassphrase) {
		t.Fatal("ErrGuessablePassphrase must match itself and ErrWeakPassphrase")
	}
	if EstimatePassphraseBits(nil) != 0 {
		t.Fatal("empty passphrase must have no entropy")
	}
	for _, w := range commonWords {
		if utf8.RuneCountInString(w) < 4 || strings.ToLower(w) != w {
			t.Errorf("word list entry %q must be lowercase and at least 4 letters", w)
		}
		for _, r := range w {
			if r >= 0x80 {
				t.Errorf("word list entry %q must be folded ASCII", w)
			}
		}
	}
}

func FuzzEstimatePassphraseBits(f *testing.F) {
	for _, p := range append(acceptedPassphrases, rejectedPassphrases...) {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if len(p) > maxPassphraseBytes {
			return
		}
		bits := EstimatePassphraseBits([]byte(p))
		if bits < 0 || bits != bits {
			t.Fatalf("estimate %v for %q", bits, p)
		}
		_ = CheckPassphrase([]byte(p))
	})
}

type constReader byte

func (c constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

type cycleReader struct{ n byte }

func (c *cycleReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.n % 16
		c.n++
	}
	return len(p), nil
}

func TestRandomHealth(t *testing.T) {
	if err := CheckRandom(rand.Reader); err != nil {
		t.Fatalf("system random: %v", err)
	}
	if err := CheckSystemRandom(); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]interface{ Read([]byte) (int, error) }{
		"zero":  constReader(0),
		"ff":    constReader(0xff),
		"cycle": &cycleReader{},
		"short": bytes.NewReader(make([]byte, 10)),
	} {
		if err := CheckRandom(r); !errors.Is(err, ErrRandomUnhealthy) {
			t.Errorf("%s source passed the health check: %v", name, err)
		}
	}
	// A fixed test source is not checked; the system source is.
	if _, err := GenerateDeviceSecrets(bytes.NewReader(bytes.Repeat([]byte{7, 1, 9, 3}, 64)), testNow); err != nil {
		t.Fatalf("deterministic source must stay usable in tests: %v", err)
	}
	if _, _, err := GenerateRootKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
}

func TestEnvelopeAlgorithm(t *testing.T) {
	_, priv, _ := GenerateRootKey(rand.Reader)
	env, err := Sign(priv, DocumentContext, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("algorithm")) {
		t.Fatal("Sign must leave the algorithm empty so older versions read the envelope")
	}
	pub := priv.Public().(ed25519.PublicKey)
	for _, alg := range []string{"", AlgEd25519} {
		e := env
		e.Algorithm = alg
		raw, _ := json.Marshal(e)
		got, err := UnmarshalEnvelope(raw)
		if err != nil {
			t.Fatalf("%q: %v", alg, err)
		}
		if _, err := got.Verify(pub, DocumentContext); err != nil {
			t.Fatalf("%q: %v", alg, err)
		}
		if got.EffectiveAlgorithm() != AlgEd25519 {
			t.Fatalf("effective algorithm %q", got.EffectiveAlgorithm())
		}
	}
	for _, alg := range []string{"ml-dsa-65", "Ed25519", "none", " ed25519"} {
		e := env
		e.Algorithm = alg
		raw, _ := json.Marshal(e)
		if _, err := UnmarshalEnvelope(raw); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("%q decoded: %v", alg, err)
		}
		if _, err := e.Verify(pub, DocumentContext); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("%q verified: %v", alg, err)
		}
	}
}

func FuzzUnmarshalEnvelope(f *testing.F) {
	_, priv, _ := GenerateRootKey(rand.Reader)
	env, _ := Sign(priv, DocumentContext, []byte(`{"a":1}`))
	good, _ := MarshalEnvelope(env)
	f.Add(good)
	f.Add([]byte(`{"context":"x","payload":"","signature":"","algorithm":"ml-dsa-65"}`))
	pub := priv.Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := UnmarshalEnvelope(data)
		if err != nil {
			return
		}
		if checkAlgorithm(e.Algorithm) != nil {
			t.Fatalf("unsupported algorithm %q decoded", e.Algorithm)
		}
		if payload, err := e.Verify(pub, DocumentContext); err == nil && !bytes.Equal(payload, []byte(`{"a":1}`)) {
			t.Fatal("forged payload verified")
		}
	})
}

func TestCalibrateArgon2(t *testing.T) {
	fixed := func(perUnit time.Duration) func(Argon2Params) time.Duration {
		return func(p Argon2Params) time.Duration {
			return perUnit * time.Duration(p.Time) * time.Duration(p.MemoryKiB/(64*1024))
		}
	}
	// Fast machine: memory first, then time, within the caps.
	p := calibrateArgon2(time.Second, fixed(20*time.Millisecond))
	if p.MemoryKiB != calibrationMaxMemory || p.Time < DefaultArgon2.Time || p.Time > calibrationMaxTime {
		t.Fatalf("fast machine params %+v", p)
	}
	// Slow machine: never below the default.
	if p := calibrateArgon2(time.Second, fixed(time.Second)); p != DefaultArgon2 {
		t.Fatalf("slow machine params %+v", p)
	}
	if p := calibrateArgon2(0, fixed(time.Millisecond)); p != DefaultArgon2 {
		t.Fatalf("disabled calibration %+v", p)
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if s := StrongerArgon2(DefaultArgon2, Argon2Params{Time: 1, MemoryKiB: 256 * 1024, Threads: 1}); s.Time != 3 || s.MemoryKiB != 256*1024 || s.Threads != 4 {
		t.Fatalf("stronger %+v", s)
	}
	if !testArgon2.WeakerThan(DefaultArgon2) || DefaultArgon2.WeakerThan(testArgon2) {
		t.Fatal("WeakerThan")
	}
}

func TestSAS(t *testing.T) {
	s, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	_, req, err := s.NewEnrollmentRequest("laptop", testNow)
	if err != nil {
		t.Fatal(err)
	}
	own, err := s.SAS()
	if err != nil {
		t.Fatal(err)
	}
	if own != req.SAS() {
		t.Fatal("device and owner must compute the same code")
	}
	if len(own) != SASDigits+sasGroups-1 || strings.Count(own, "-") != sasGroups-1 {
		t.Fatalf("format %q", own)
	}
	if !SASMatches(strings.ReplaceAll(own, "-", " "), own) || SASMatches("", own) || SASMatches(own[:10], own) {
		t.Fatal("SASMatches")
	}
	other, _ := GenerateDeviceSecrets(rand.Reader, testNow)
	if o, _ := other.SAS(); o == own {
		t.Fatal("different devices produced the same code")
	}
	_, root, _ := GenerateRootKey(rand.Reader)
	if RootSAS(root.Public().(ed25519.PublicKey)) == own {
		t.Fatal("root and device codes must be domain separated")
	}
}

func TestPaperBackup(t *testing.T) {
	_, priv, _ := GenerateRootKey(rand.Reader)
	pass := []byte("kağıt yedek parolası 61")
	sealed, err := SealRootKey(priv, pass, testArgon2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := EncodePaperBackup(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) != PaperBackupSize || PaperBackupSize != 130 {
		t.Fatalf("packed size %d", len(packed))
	}
	lines := PaperLines(packed)
	if len(lines) != 13 {
		t.Fatalf("%d lines", len(lines))
	}
	for _, text := range []string{strings.Join(lines, "\n"), PaperQRText(packed), strings.ToLower(strings.Join(lines, "\r\n"))} {
		got, err := ParsePaperBackup(text)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		restored, err := DecodePaperBackup(got)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := restored.Open(pass)
		if err != nil {
			t.Fatalf("open restored: %v", err)
		}
		if !bytes.Equal(opened, priv) {
			t.Fatal("restored key differs")
		}
	}
	// A typo is reported on its line.
	bad := append([]string(nil), lines...)
	r := []byte(bad[4])
	if r[3] == 'A' {
		r[3] = 'B'
	} else {
		r[3] = 'A'
	}
	bad[4] = string(r)
	if _, err := ParsePaperBackup(strings.Join(bad, "\n")); !errors.Is(err, ErrPaperChecksum) || !strings.Contains(err.Error(), "line 5") {
		t.Fatalf("typo error = %v", err)
	}
	// A changed KDF parameter fails to decrypt (bound as additional data).
	tampered := append([]byte(nil), packed...)
	tampered[4]++
	if s, err := DecodePaperBackup(tampered); err == nil {
		if _, err := s.Open(pass); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("tampered backup opened: %v", err)
		}
	}
}

func FuzzParsePaperBackup(f *testing.F) {
	_, priv, _ := GenerateRootKey(rand.Reader)
	sealed, _ := SealRootKey(priv, []byte("kağıt yedek parolası 61"), testArgon2, rand.Reader)
	packed, _ := EncodePaperBackup(sealed)
	f.Add(strings.Join(PaperLines(packed), "\n"))
	f.Add(PaperQRText(packed))
	f.Add("01 AAAA  AA")
	f.Fuzz(func(t *testing.T, text string) {
		got, err := ParsePaperBackup(text)
		if err != nil {
			return
		}
		if _, err := DecodePaperBackup(got); err != nil {
			t.Fatalf("parsed backup does not decode: %v", err)
		}
	})
}

func TestMemoryLock(t *testing.T) {
	key := make([]byte, 64)
	copy(key, "secret key material")
	locked := LockKey(key)
	if MemoryLockSupported() && !locked {
		t.Log("memory lock unavailable in this environment (limit reached)")
	}
	if LockKey(key) != locked {
		t.Fatal("locking the same buffer twice must be idempotent")
	}
	WipeKey(key)
	if !bytes.Equal(key, make([]byte, 64)) {
		t.Fatal("WipeKey must zero the buffer")
	}
	memlock.Lock()
	_, still := memlock.ranges[uintptr(unsafe.Pointer(unsafe.SliceData(key)))]
	memlock.Unlock()
	if still {
		t.Fatal("wiped key is still registered as locked")
	}
	WipeKey(nil)
	WipeKey(make([]byte, 8)) // never locked

	s, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := MarshalDeviceSecrets(s)
	loaded, err := UnmarshalDeviceSecrets(data)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Wipe()
	if !bytes.Equal(loaded.SigningSeed, make([]byte, 32)) || !bytes.Equal(loaded.WireGuardPrivate, make([]byte, 32)) {
		t.Fatal("DeviceSecrets.Wipe must zero the keys")
	}
}
