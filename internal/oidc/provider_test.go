package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	issuer   = "https://idp.nas.openscale.internal:4051"
	redirect = "https://grafana.nas.openscale.internal:4051/login/generic_oauth"
	secret   = "cok-gizli-istemci-sirri"
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func newProvider(t *testing.T, allow *bool) *Provider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(secret))
	p, err := New(Config{
		Issuer:  func() string { return issuer },
		Clients: []Client{{ID: "grafana", SecretSHA256: hex.EncodeToString(sum[:]), RedirectURIs: []string{redirect}}, {ID: "cli", RedirectURIs: []string{"http://127.0.0.1:9999/cb"}}},
		Key:     key,
		Identity: func(*http.Request) (Subject, bool) {
			return Subject{ID: "dev-id-1", Name: "laptop", FQDN: "laptop.openscale.internal", Tags: []string{"aile"}}, *allow
		},
		Now: func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func authorizeURL(client, redir, chal string) string {
	v := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redir}, "scope": {"openid profile"}, "state": {"st1"}, "nonce": {"n1"}, "code_challenge": {chal}, "code_challenge_method": {"S256"}}
	return PathAuthorize + "?" + v.Encode()
}

func call(p *Provider, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func getCode(t *testing.T, p *Provider) string {
	t.Helper()
	w := call(p, httptest.NewRequest("GET", authorizeURL("grafana", redirect, challenge(verifier)), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), redirect) || loc.Query().Get("state") != "st1" || loc.Query().Get("code") == "" {
		t.Fatalf("redirect: %s", loc)
	}
	return loc.Query().Get("code")
}

func tokenRequest(code, ver string, basic bool) *http.Request {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {ver}}
	if !basic {
		form.Set("client_id", "grafana")
		form.Set("client_secret", secret)
	}
	r := httptest.NewRequest("POST", PathToken, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		r.SetBasicAuth("grafana", secret)
	}
	return r
}

func TestCodeFlowWithPKCE(t *testing.T) {
	allow := true
	p := newProvider(t, &allow)
	code := getCode(t, p)
	w := call(p, tokenRequest(code, verifier, true))
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	claims := verifyJWT(t, p, tok.IDToken)
	if claims["sub"] != "dev-id-1" || claims["aud"] != "grafana" || claims["iss"] != issuer || claims["nonce"] != "n1" || claims["preferred_username"] != "laptop" {
		t.Fatalf("claims: %v", claims)
	}
	// The code is single use.
	if w := call(p, tokenRequest(code, verifier, true)); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("replay: %d %s", w.Code, w.Body)
	}
	// userinfo with the access token.
	r := httptest.NewRequest("GET", PathUserinfo, nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	if w := call(p, r); w.Code != 200 || !strings.Contains(w.Body.String(), `"laptop"`) {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body)
	}
	r.Header.Set("Authorization", "Bearer yanlis")
	if w := call(p, r); w.Code != 401 {
		t.Fatalf("userinfo bad token: %d", w.Code)
	}
}

func TestTokenRefusals(t *testing.T) {
	allow := true
	p := newProvider(t, &allow)
	// Wrong verifier burns the code.
	code := getCode(t, p)
	if w := call(p, tokenRequest(code, strings.Repeat("a", 43), false)); w.Code != 400 {
		t.Fatalf("wrong verifier: %d", w.Code)
	}
	if w := call(p, tokenRequest(code, verifier, false)); w.Code != 400 {
		t.Fatalf("code reused after failure: %d", w.Code)
	}
	// Wrong secret.
	code = getCode(t, p)
	r := tokenRequest(code, verifier, false)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "client_id": {"grafana"}, "client_secret": {"yanlis"}}
	r = httptest.NewRequest("POST", PathToken, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := call(p, r); w.Code != 401 {
		t.Fatalf("wrong secret: %d", w.Code)
	}
	// GET to the token endpoint.
	if w := call(p, httptest.NewRequest("GET", PathToken, nil)); w.Code != 405 {
		t.Fatalf("GET token: %d", w.Code)
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	allow := true
	p := newProvider(t, &allow)
	// Unknown client and unregistered redirect never redirect.
	for _, u := range []string{
		authorizeURL("yok", redirect, challenge(verifier)),
		authorizeURL("grafana", "https://saldirgan.example.org/cb", challenge(verifier)),
		authorizeURL("grafana", redirect+"/ek", challenge(verifier)),
	} {
		w := call(p, httptest.NewRequest("GET", u, nil))
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("%s: %d %q", u, w.Code, w.Header().Get("Location"))
		}
	}
	// PKCE is required, plain is refused.
	u := strings.Replace(authorizeURL("grafana", redirect, challenge(verifier)), "S256", "plain", 1)
	w := call(p, httptest.NewRequest("GET", u, nil))
	if loc := w.Header().Get("Location"); w.Code != 302 || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("plain pkce: %d %s", w.Code, loc)
	}
	// A source that is not an allowed device gets access_denied.
	allow = false
	w = call(p, httptest.NewRequest("GET", authorizeURL("grafana", redirect, challenge(verifier)), nil))
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("denied: %s", loc)
	}
	// Duplicate parameters.
	w = call(p, httptest.NewRequest("GET", authorizeURL("grafana", redirect, challenge(verifier))+"&client_id=cli", nil))
	if w.Code != 400 {
		t.Fatalf("duplicate: %d", w.Code)
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	allow := true
	p := newProvider(t, &allow)
	w := call(p, httptest.NewRequest("GET", PathDiscovery, nil))
	var d map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || d["issuer"] != issuer || d["token_endpoint"] != issuer+PathToken {
		t.Fatalf("discovery: %v %v", err, d)
	}
}

// verifyJWT checks an ES256 token with the provider's JWKS.
func verifyJWT(t *testing.T, p *Provider, tok string) map[string]any {
	t.Helper()
	w := call(p, httptest.NewRequest("GET", PathJWKS, nil))
	var set struct {
		Keys []struct{ Kid, X, Y string } `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks: %v", err)
	}
	b := base64.RawURLEncoding
	xb, _ := b.DecodeString(set.Keys[0].X)
	yb, _ := b.DecodeString(set.Keys[0].Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	sig, _ := b.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
	var hdr map[string]string
	hb, _ := b.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr["alg"] != "ES256" || hdr["kid"] != set.Keys[0].Kid {
		t.Fatalf("header: %v", hdr)
	}
	body, _ := b.DecodeString(parts[1])
	var c map[string]any
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
