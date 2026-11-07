package panel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

// g5Dir returns a per-test folder inside the package (never the system
// temporary directory) and removes it afterwards.
func g5Dir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("testdata", ".g5tmp", strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Join("testdata", ".g5tmp"))
	})
	return dir
}

type g5Clock struct{ t atomic.Int64 }

func (c *g5Clock) now() time.Time      { return time.Unix(0, c.t.Load()) }
func (c *g5Clock) add(d time.Duration) { c.t.Add(int64(d)) }
func newClock() *g5Clock               { c := &g5Clock{}; c.t.Store(time.Now().UnixNano()); return c }
func cookieOf(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func g5Server(t *testing.T, clock *g5Clock) *Server {
	t.Helper()
	dir := filepath.Join(g5Dir(t), "net")
	n, err := admin.Init(dir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity},
		[]byte(testPass), admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{"index.html": {Data: []byte(`<html></html>`)}, "login/index.html": {Data: []byte(`<html></html>`)}}
	cfg := Config{Network: n, Files: files}
	if clock != nil {
		cfg.Now = clock.now
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.host = testHost
	srv.SetAdminTokenProbe(func(context.Context) (bool, error) { return true, nil })
	return srv
}

func both(fs ...func(*http.Request)) func(*http.Request) {
	return func(r *http.Request) {
		for _, f := range fs {
			f(r)
		}
	}
}

func csrfOf(t *testing.T, h http.Handler, c *http.Cookie) string {
	t.Helper()
	rec := do(t, h, http.MethodGet, "/api/session", nil, cookieOf(c))
	var sess struct{ CSRFToken string }
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil || sess.CSRFToken == "" {
		t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
	return sess.CSRFToken
}

func writeReq(c *http.Cookie, csrf string) func(*http.Request) {
	return both(withOrigin, cookieOf(c), func(r *http.Request) { r.Header.Set("X-CSRF-Token", csrf) })
}

func codeOf(rec *httptest.ResponseRecorder) string {
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	s, _ := m["code"].(string)
	return s
}

// --- CBOR ---

// cborEnc is a tiny encoder for test vectors.
func cborHeadEnc(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	}
	return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
}

func cborInt64(v int64) []byte {
	if v >= 0 {
		return cborHeadEnc(0, uint64(v))
	}
	return cborHeadEnc(1, uint64(-1-v))
}

func cborBytesEnc(b []byte) []byte { return append(cborHeadEnc(2, uint64(len(b))), b...) }
func cborText(s string) []byte     { return append(cborHeadEnc(3, uint64(len(s))), s...) }

func cborMap(pairs ...[]byte) []byte {
	out := cborHeadEnc(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func TestCBORDecoder(t *testing.T) {
	v, rest, err := cborDecode(cborMap(cborInt64(1), cborInt64(2), cborInt64(-1), cborBytesEnc([]byte{1, 2}), cborText("a"), cborText("ç")))
	if err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	m := v.(map[any]any)
	if m[int64(1)] != int64(2) || !bytes.Equal(m[int64(-1)].([]byte), []byte{1, 2}) || m["a"] != "ç" {
		t.Fatalf("%v", m)
	}
	for _, bad := range [][]byte{
		{0x5f},                         // indefinite byte string
		{0x9f},                         // indefinite array
		{0x5a, 0xff, 0xff},             // truncated length
		{0x59, 0xff, 0xff},             // length beyond input
		{0xa1, 0x41, 0x00, 0x01},       // byte string map key
		{0xa2, 0x01, 0x01, 0x01, 0x01}, // duplicate key
		{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}, // float
		bytes.Repeat([]byte{0x81}, 20), // nesting
	} {
		if _, _, err := cborDecode(bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}

// --- WebAuthn ---

type fakeAuthenticator struct {
	ec      *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
	credID  []byte
	counter uint32
	rpID    string
	origin  string
	noUP    bool
}

func (a *fakeAuthenticator) coseKey() []byte {
	if a.ed != nil {
		return cborMap(cborInt64(1), cborInt64(1), cborInt64(3), cborInt64(coseEdDSA), cborInt64(-1), cborInt64(6),
			cborInt64(-2), cborBytesEnc(a.ed.Public().(ed25519.PublicKey)))
	}
	pub, _ := a.ec.PublicKey.Bytes()
	return cborMap(cborInt64(1), cborInt64(2), cborInt64(3), cborInt64(coseES256), cborInt64(-1), cborInt64(1),
		cborInt64(-2), cborBytesEnc(pub[1:33]), cborInt64(-3), cborBytesEnc(pub[33:]))
}

func (a *fakeAuthenticator) authData(withCred bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	flags := byte(flagUP)
	if a.noUP {
		flags = 0
	}
	if withCred {
		flags |= flagAT
	}
	b := append(rp[:], flags)
	b = binary.BigEndian.AppendUint32(b, a.counter)
	if withCred {
		b = append(b, make([]byte, 16)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.credID)))
		b = append(b, a.credID...)
		b = append(b, a.coseKey()...)
	}
	return b
}

func clientDataFor(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": b64url.EncodeToString(challenge), "origin": origin})
	return b
}

func (a *fakeAuthenticator) register(challenge []byte) RegistrationResponse {
	att := cborMap(cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(), cborText("authData"), cborBytesEnc(a.authData(true)))
	return RegistrationResponse{ClientDataJSON: b64url.EncodeToString(clientDataFor("webauthn.create", challenge, a.origin)), AttestationObject: b64url.EncodeToString(att), Name: "YubiKey"}
}

func (a *fakeAuthenticator) assert(challenge []byte) AssertionResponse {
	a.counter++
	ad := a.authData(false)
	cd := clientDataFor("webauthn.get", challenge, a.origin)
	h := sha256.Sum256(cd)
	msg := append(append([]byte(nil), ad...), h[:]...)
	var sig []byte
	if a.ed != nil {
		sig = ed25519.Sign(a.ed, msg)
	} else {
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, a.ec, d[:])
	}
	return AssertionResponse{CredentialID: b64url.EncodeToString(a.credID), ClientDataJSON: b64url.EncodeToString(cd),
		AuthenticatorData: b64url.EncodeToString(ad), Signature: b64url.EncodeToString(sig)}
}

func newAuthenticator(t *testing.T, ed bool) *fakeAuthenticator {
	a := &fakeAuthenticator{credID: []byte("cred-" + t.Name()), rpID: "localhost", origin: "http://localhost:4321"}
	if ed {
		_, a.ed, _ = ed25519.GenerateKey(rand.Reader)
	} else {
		a.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return a
}

func TestWebAuthnVerify(t *testing.T) {
	origins := []string{"http://localhost:4321"}
	for _, ed := range []bool{false, true} {
		a := newAuthenticator(t, ed)
		ch := []byte("kayit-meydan-okumasi-32-bayt....")
		cred, err := verifyRegistration(a.register(ch), ch, "localhost", origins, time.Now())
		if err != nil {
			t.Fatalf("ed=%v register: %v", ed, err)
		}
		if _, err := verifyRegistration(a.register(ch), []byte("baska"), "localhost", origins, time.Now()); err == nil {
			t.Fatal("wrong challenge accepted")
		}
		if _, err := verifyRegistration(a.register(ch), ch, "localhost", []string{"http://evil.example"}, time.Now()); err == nil {
			t.Fatal("wrong origin accepted")
		}
		creds := []WebAuthnCredential{cred}
		ch2 := []byte("giris-meydan-okumasi")
		idx, count, err := verifyAssertion(a.assert(ch2), creds, ch2, "localhost", origins)
		if err != nil || idx != 0 || count != 1 {
			t.Fatalf("ed=%v assert: %v %d %d", ed, err, idx, count)
		}
		creds[0].SignCount = count
		// A replayed or cloned assertion with an old counter is refused.
		a.counter = 0
		if _, _, err := verifyAssertion(a.assert(ch2), creds, ch2, "localhost", origins); err == nil {
			t.Fatal("counter regression accepted")
		}
		a.counter = 10
		resp := a.assert(ch2)
		bad := resp
		sig, _ := b64url.DecodeString(bad.Signature)
		sig[len(sig)-1] ^= 1
		bad.Signature = b64url.EncodeToString(sig)
		if _, _, err := verifyAssertion(bad, creds, ch2, "localhost", origins); err == nil {
			t.Fatal("bad signature accepted")
		}
		a.rpID = "evil.example"
		if _, _, err := verifyAssertion(a.assert(ch2), creds, ch2, "localhost", origins); err == nil {
			t.Fatal("wrong RP accepted")
		}
		a.rpID, a.noUP = "localhost", true
		if _, _, err := verifyAssertion(a.assert(ch2), creds, ch2, "localhost", origins); err == nil {
			t.Fatal("assertion without user presence accepted")
		}
	}
}

// --- TOTP ---

func TestTOTPVectorsAndReplay(t *testing.T) {
	seed := []byte("12345678901234567890") // RFC 6238 appendix B, SHA-1
	if got := totpCode(seed, 59/30); got != "287082" {
		t.Fatalf("T=59: %s", got)
	}
	if got := totpCode(seed, 1111111109/30); got != "081804" {
		t.Fatalf("T=1111111109: %s", got)
	}
	now := time.Unix(1111111109, 0)
	step, ok := totpCheck(seed, "081804", now, 0)
	if !ok {
		t.Fatal("valid code refused")
	}
	if _, ok := totpCheck(seed, "081804", now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := totpCheck(seed, "081804", now.Add(2*time.Minute), 0); ok {
		t.Fatal("old code accepted")
	}
	for _, bad := range []string{"", "12345", "abcdef", "1234567"} {
		if _, ok := totpCheck(seed, bad, now, 0); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
	if !strings.HasPrefix(totpURI(seed, "panel"), "otpauth://totp/OpenScale:panel?") {
		t.Fatal(totpURI(seed, "panel"))
	}
}

func TestSeedSealing(t *testing.T) {
	seed := []byte("12345678901234567890")
	sealed, err := sealSeedWithPassword(seed, []byte("parola"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Box, seed) {
		t.Fatal("seed stored in the clear")
	}
	got, err := sealed.open(deriveSealKey([]byte("parola"), sealed.Salt))
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("open: %v", err)
	}
	if _, err := sealed.open(deriveSealKey([]byte("yanlis"), sealed.Salt)); err == nil {
		t.Fatal("wrong password opened the seed")
	}
}

// --- flows ---

func loginRaw(t *testing.T, h http.Handler, mutate ...func(*http.Request)) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, both(append([]func(*http.Request){withOrigin}, mutate...)...))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	return rec, rec.Result().Cookies()[0]
}

func TestTOTPEnrolAndSecondFactor(t *testing.T) {
	clock := newClock()
	srv := g5Server(t, clock)
	h := srv.Handler()
	_, c := loginRaw(t, h)
	csrf := csrfOf(t, h, c)
	rec := do(t, h, http.MethodPost, "/api/auth/totp/enroll/begin", map[string]string{"passphrase": testPass}, writeReq(c, csrf))
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll begin: %d %s", rec.Code, rec.Body)
	}
	var en totpEnrollResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &en)
	seed, err := b32Decode(en.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := totpCode(seed, uint64(clock.now().Unix())/totpPeriod)
	if rec := do(t, h, http.MethodPost, "/api/auth/totp/enroll/finish", map[string]string{"code": code}, writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("enroll finish: %d %s", rec.Code, rec.Body)
	}
	raw, _ := os.ReadFile(filepath.Join(srv.panelDir(), PanelAuthFile))
	if bytes.Contains(raw, []byte(en.Secret)) || bytes.Contains(raw, seed) {
		t.Fatal("seed written in the clear")
	}
	if rec := do(t, h, http.MethodPost, "/api/auth/settings", map[string]any{"local_mfa": true}, writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	srv.dropSettingsCache()

	rec, c2 := loginRaw(t, h)
	var lr loginResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)
	if !lr.MFARequired || len(lr.Methods) != 1 || lr.Methods[0] != "totp" {
		t.Fatalf("login answer: %s", rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, cookieOf(c2)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pending session reached the API: %d", rec.Code)
	}
	// The code used at enrolment cannot be used again.
	if rec := do(t, h, http.MethodPost, "/api/auth/mfa/totp", map[string]string{"code": code}, both(withOrigin, cookieOf(c2))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d", rec.Code)
	}
	clock.add(30 * time.Second)
	if rec := do(t, h, http.MethodPost, "/api/auth/mfa/totp", map[string]string{"code": "000000"}, both(cookieOf(c2))); rec.Code != http.StatusForbidden {
		t.Fatalf("missing Origin: %d", rec.Code)
	}
	next := totpCode(seed, uint64(clock.now().Unix())/totpPeriod)
	if rec := do(t, h, http.MethodPost, "/api/auth/mfa/totp", map[string]string{"code": next}, both(withOrigin, cookieOf(c2))); rec.Code != http.StatusOK {
		t.Fatalf("second factor: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, cookieOf(c2)); rec.Code != http.StatusOK {
		t.Fatalf("full session refused: %d", rec.Code)
	}
}

func b32Decode(s string) ([]byte, error) {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var out []byte
	var buf, bits uint64
	for _, c := range s {
		i := strings.IndexRune(alpha, c)
		if i < 0 {
			return nil, errors.New("base32")
		}
		buf = buf<<5 | uint64(i)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}

func TestWebAuthnRegistrationAndLogin(t *testing.T) {
	srv := g5Server(t, nil)
	h := srv.Handler()
	_, c := loginRaw(t, h)
	csrf := csrfOf(t, h, c)
	// Registration needs a fresh proof.
	if rec := do(t, h, http.MethodPost, "/api/auth/webauthn/register/begin", map[string]string{}, writeReq(c, csrf)); codeOf(rec) != "reauth_required" {
		t.Fatalf("register without proof: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/auth/reauth", map[string]string{"passphrase": testPass}, writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("reauth: %d %s", rec.Code, rec.Body)
	}
	rec := do(t, h, http.MethodPost, "/api/auth/webauthn/register/begin", map[string]string{}, writeReq(c, csrf))
	var ch challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil || rec.Code != http.StatusOK || ch.RPID != "localhost" || ch.Attestation != "none" {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	chal, _ := b64url.DecodeString(ch.Challenge)
	a := newAuthenticator(t, false)
	if rec := do(t, h, http.MethodPost, "/api/auth/webauthn/register", a.register(chal), writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/auth/settings", map[string]any{"local_mfa": true}, writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	srv.dropSettingsCache()
	rec, c2 := loginRaw(t, h)
	if !strings.Contains(rec.Body.String(), `"mfa_required":true`) {
		t.Fatalf("login: %s", rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/auth/mfa/webauthn/begin", map[string]string{}, both(withOrigin, cookieOf(c2)))
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	chal, _ = b64url.DecodeString(ch.Challenge)
	// The challenge is single use: a wrong origin spends it.
	a.origin = "http://evil.example"
	if rec := do(t, h, http.MethodPost, "/api/auth/mfa/webauthn/finish", a.assert(chal), both(withOrigin, cookieOf(c2))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong origin: %d", rec.Code)
	}
	a.origin = "http://localhost:4321"
	rec = do(t, h, http.MethodPost, "/api/auth/mfa/webauthn/begin", map[string]string{}, both(withOrigin, cookieOf(c2)))
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	chal, _ = b64url.DecodeString(ch.Challenge)
	if rec := do(t, h, http.MethodPost, "/api/auth/mfa/webauthn/finish", a.assert(chal), both(withOrigin, cookieOf(c2))); rec.Code != http.StatusOK {
		t.Fatalf("assertion: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, cookieOf(c2)); rec.Code != http.StatusOK {
		t.Fatalf("after security key: %d", rec.Code)
	}
}

func TestSessionContextBinding(t *testing.T) {
	srv := g5Server(t, nil)
	h := srv.Handler()
	wv := func(r *http.Request) { r.Header.Set(WebViewHeader, "pencere-1") }
	_, c := loginRaw(t, h, wv)
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, both(cookieOf(c), wv)); rec.Code != http.StatusOK {
		t.Fatalf("same context: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, both(cookieOf(c), func(r *http.Request) { r.Header.Set(WebViewHeader, "pencere-2") })); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other WebView: %d", rec.Code)
	}
	// The session is gone, even from the original window.
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, both(cookieOf(c), wv)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("dropped session still works: %d", rec.Code)
	}
	_, c2 := loginRaw(t, h)
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, both(cookieOf(c2), func(r *http.Request) { r.RemoteAddr = "198.51.100.7:5555" })); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other source address: %d", rec.Code)
	}
}

func TestReauthForCriticalActions(t *testing.T) {
	srv := g5Server(t, nil)
	if _, err := UpdatePanelAuth(srv.panelDir(), func(p *PanelAuth) error { p.ReauthCritical = true; return nil }); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	_, c := loginRaw(t, h)
	csrf := csrfOf(t, h, c)
	body := map[string]any{"passphrase": testPass}
	if rec := do(t, h, http.MethodPost, "/api/invites", body, writeReq(c, csrf)); codeOf(rec) != "reauth_required" {
		t.Fatalf("invite without proof: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/auth/reauth", map[string]string{"passphrase": "yanlış parola"}, writeReq(c, csrf)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong reauth: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/auth/reauth", map[string]string{"passphrase": testPass}, writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("reauth: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/invites", body, writeReq(c, csrf)); codeOf(rec) == "reauth_required" {
		t.Fatal("proof not accepted")
	}
	if rec := do(t, h, http.MethodPost, "/api/invites", body, writeReq(c, csrf)); codeOf(rec) != "reauth_required" {
		t.Fatal("proof used twice")
	}
	// Non-critical changes do not ask.
	if rec := do(t, h, http.MethodPost, "/api/network/name", map[string]any{"passphrase": testPass, "name": "Ev"}, writeReq(c, csrf)); codeOf(rec) == "reauth_required" {
		t.Fatal("ordinary change asked for a proof")
	}
}

func TestAdminModeExpiresAndFollowsToken(t *testing.T) {
	clock := newClock()
	srv := g5Server(t, clock)
	if _, err := UpdatePanelAuth(srv.panelDir(), func(p *PanelAuth) error { p.AdminMode, p.AdminToken = true, true; return nil }); err != nil {
		t.Fatal(err)
	}
	var present atomic.Bool
	present.Store(true)
	srv.SetAdminTokenProbe(func(context.Context) (bool, error) { return present.Load(), nil })
	h := srv.Handler()
	_, c := loginRaw(t, h)
	csrf := csrfOf(t, h, c)
	change := func() *httptest.ResponseRecorder {
		return do(t, h, http.MethodPost, "/api/network/name", map[string]any{"passphrase": testPass, "name": "Ev"}, writeReq(c, csrf))
	}
	if rec := change(); codeOf(rec) == "admin_mode_required" {
		t.Fatalf("fresh sign-in is not in administrator mode: %s", rec.Body)
	}
	// Stay active (the session itself ends after 15 idle minutes).
	for range 4 {
		clock.add(4 * time.Minute)
		do(t, h, http.MethodGet, "/api/overview", nil, cookieOf(c))
	}
	srv.dropSettingsCache()
	if rec := change(); codeOf(rec) != "admin_mode_required" {
		t.Fatalf("after 16 minutes: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, cookieOf(c)); rec.Code != http.StatusOK {
		t.Fatalf("reads must keep working: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/auth/reauth", map[string]string{"passphrase": testPass}, writeReq(c, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("reauth: %d", rec.Code)
	}
	if rec := change(); codeOf(rec) == "admin_mode_required" {
		t.Fatal("proof did not restart the mode")
	}
	// Removing the key ends the mode at once; putting it back is not enough.
	present.Store(false)
	clock.add(3 * time.Second)
	if rec := change(); codeOf(rec) != "admin_mode_required" {
		t.Fatal("mode survived the key's removal")
	}
	present.Store(true)
	clock.add(3 * time.Second)
	if rec := change(); codeOf(rec) != "admin_mode_required" {
		t.Fatal("reinserted key restored the mode without a proof")
	}
	rec := do(t, h, http.MethodGet, "/api/auth/status", nil, cookieOf(c))
	var st authStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || !st.AdminMode || st.AdminActive || !st.SignedIn {
		t.Fatalf("status: %s", rec.Body)
	}
}

func TestBrokenAuthFileFailsClosed(t *testing.T) {
	srv := g5Server(t, nil)
	if err := os.WriteFile(filepath.Join(srv.panelDir(), PanelAuthFile), []byte(`{"version":1,"admin_mode":false,"bilinmeyen":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	set := srv.authSettings()
	if !set.AdminMode || !set.ReauthCritical {
		t.Fatalf("broken file switched protections off: %+v", set)
	}
}

// --- SSH terminal bridge ---

type miniSSHD struct {
	addr netip.AddrPort
	key  ssh.Signer
}

func startMiniSSHD(t *testing.T, user, pass string) *miniSSHD {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if m.User() == user && string(pw) == pass {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("hayır")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, rq, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range rq {
							_ = r.Reply(r.Type == "pty-req" || r.Type == "shell" || r.Type == "window-change", nil)
							if r.Type == "shell" {
								go func() {
									buf := make([]byte, 256)
									for {
										n, err := ch.Read(buf)
										if n > 0 {
											_, _ = ch.Write(append([]byte("cevap:"), buf[:n]...))
										}
										if err != nil {
											return
										}
									}
								}()
							}
						}
					}()
				}
			}()
		}
	}()
	return &miniSSHD{addr: ln.Addr().(*net.TCPAddr).AddrPort(), key: signer}
}

func TestSSHTerminalBridge(t *testing.T) {
	target := startMiniSSHD(t, "ayse", "linux-parolasi")
	srv := g5Server(t, nil)
	srv.SetSSHResolver(func(name string) (netip.Addr, bool) {
		return target.addr.Addr(), name == "sunucu"
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	srv.host = host
	origin := func(r *http.Request) {
		r.Host = host
		r.Header.Set("Origin", "http://"+host)
	}
	post := func(path string, body any, c *http.Cookie, csrf string) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		origin(req)
		if c != nil {
			req.AddCookie(c)
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post("/api/login", map[string]string{"passphrase": testPass}, nil, "")
	c := resp.Cookies()[0]
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/session", nil)
	req.AddCookie(c)
	resp, _ = http.DefaultClient.Do(req)
	var sess struct{ CSRFToken string }
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()

	open := func() string {
		resp := post("/api/ssh/open", map[string]any{"device": "sunucu", "port": int(target.addr.Port()), "user": "ayse"}, c, sess.CSRFToken)
		defer resp.Body.Close()
		var out struct{ Ticket string }
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != http.StatusOK || out.Ticket == "" {
			t.Fatalf("open: %d", resp.StatusCode)
		}
		return out.Ticket
	}
	dialWS := func(ticket, originHdr string) (*websocket.Conn, error) {
		cfg, _ := websocket.NewConfig("ws://"+host+"/api/ssh/ws?ticket="+ticket, originHdr)
		cfg.Header = http.Header{"Cookie": {c.Name + "=" + c.Value}}
		return websocket.DialConfig(cfg)
	}
	// Wrong Origin and unknown tickets are refused before any upgrade.
	if ws, err := dialWS(open(), "http://evil.example"); err == nil {
		ws.Close()
		t.Fatal("cross-origin WebSocket accepted")
	}
	if ws, err := dialWS("uydurma", "http://"+host); err == nil {
		ws.Close()
		t.Fatal("unknown ticket accepted")
	}
	ticket := open()
	ws, err := dialWS(ticket, "http://"+host)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if ws2, err := dialWS(ticket, "http://"+host); err == nil {
		ws2.Close()
		t.Fatal("ticket used twice")
	}
	auth, _ := json.Marshal(wsAuth{Type: "auth", Password: []byte("linux-parolasi"), Cols: 100, Rows: 30})
	if err := websocket.Message.Send(ws, string(auth)); err != nil {
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var m wsMessage
	var text string
	if err := websocket.Message.Receive(ws, &text); err != nil || json.Unmarshal([]byte(text), &m) != nil || m.Type != "hostkey" || m.Status != "pinned" ||
		m.Fingerprint != ssh.FingerprintSHA256(target.key.PublicKey()) {
		t.Fatalf("hostkey message: %v %q", err, text)
	}
	if err := websocket.Message.Receive(ws, &text); err != nil || !strings.Contains(text, `"ready"`) {
		t.Fatalf("ready: %v %q", err, text)
	}
	data, _ := json.Marshal(wsMessage{Type: "data", Data: "ls\r"})
	if err := websocket.Message.Send(ws, string(data)); err != nil {
		t.Fatal(err)
	}
	var out []byte
	if err := websocket.Message.Receive(ws, &out); err != nil || !strings.Contains(string(out), "cevap:ls") {
		t.Fatalf("terminal output: %v %q", err, out)
	}
	ws.Close()

	// A wrong password ends with auth_failed.
	ws3, err := dialWS(open(), "http://"+host)
	if err != nil {
		t.Fatal(err)
	}
	defer ws3.Close()
	auth, _ = json.Marshal(wsAuth{Type: "auth", Password: []byte("yanlış")})
	_ = websocket.Message.Send(ws3, string(auth))
	_ = ws3.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := websocket.Message.Receive(ws3, &text); err != nil || !strings.Contains(text, "auth_failed") {
		t.Fatalf("wrong password: %v %q", err, text)
	}
	var mu sync.Mutex
	mu.Lock()
	mu.Unlock()
}
