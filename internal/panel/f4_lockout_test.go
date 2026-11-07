package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

func nowForLockTest() time.Time { return time.Unix(1_800_000_000, 0) }

// The audit finding: POST /api/login needs no session, so any local
// process can send wrong passphrases. That must not lock signing, which
// only a signed-in owner can reach.
func TestLoginFailuresDoNotLockSigning(t *testing.T) {
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	h := srv.Handler()
	for i := 0; i < lockoutFailures+1; i++ {
		do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": "yanlış parola 123456"}, withOrigin)
	}
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+testHost)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	rec := do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("imzalama girişi dolduran başka süreç yüzünden engellendi: %d %s", rec.Code, rec.Body)
	}
}

// One source's failures lock that source only; the owner's window and the
// other user's process do not share a counter.
func TestLoginLockoutIsPerSource(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	var source string
	srv.g5.desk.lockSource = func(*http.Request) string { return source }

	source = "yerel:S-1-5-21-saldirgan"
	for i := 0; i < lockoutFailures; i++ {
		rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": "yanlış parola 123456"}, withOrigin)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("deneme %d = %d", i, rec.Code)
		}
	}
	rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, withOrigin)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("kilitlenen kaynak: %d, want 429 (kaba kuvvet sınırı kalmalı)", rec.Code)
	}

	if srv.auth.passphraseLocked() || srv.auth.loginLocked(lockSourceTray) {
		t.Fatal("giriş denemeleri imzalamayı veya tepsinin panik düğmesini kilitledi")
	}

	source = lockSourceWindow
	rec = do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, withOrigin)
	if rec.Code != http.StatusOK {
		t.Fatalf("sahibin penceresi başka kaynağın kilidine takıldı: %d %s", rec.Code, rec.Body)
	}
}

// Signing failures still lock signing, and only signing.
func TestSigningFailuresDoNotLockLogin(t *testing.T) {
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	h := srv.Handler()
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+testHost)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for i := 0; i < lockoutFailures; i++ {
		do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": "yanlış parola 123456"}, auth)
	}
	if rec := do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": testPass}, auth); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("imzalama kilidi = %d, want 429", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, withOrigin); rec.Code != http.StatusOK {
		t.Fatalf("giriş imzalama kilidine takıldı: %d", rec.Code)
	}
}

// New sources cannot buy new guesses without limit: a process id is never
// the key, and the table of sources is bounded with a shared last bucket.
func TestLoginLockSourcesAreBounded(t *testing.T) {
	a := newAuth(defaultRandom, nowForLockTest)
	for i := range maxLoginSources * 3 {
		src := "yerel:" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		for range lockoutFailures {
			a.recordLoginFailure(src)
		}
	}
	if n := len(a.loginFailures); n > maxLoginSources+1 {
		t.Fatalf("kaynak tablosu sınırsız büyüyor: %d", n)
	}
	if !a.loginLocked("hiç görülmemiş kaynak") {
		t.Fatal("tablo dolunca yeni kaynak taze deneme hakkı kazandı")
	}
}

// Real loopback: the classification names the OpenScale program behind
// the connection (Windows) and never fails open on a connection it cannot
// resolve.
func TestLoginSourceOverRealLoopback(t *testing.T) {
	srv := newTestServer(t)
	sources := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sources <- srv.loginSource(r)
	}))
	defer ts.Close()
	body, _ := json.Marshal(map[string]string{})
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := <-sources
	if got == "" {
		t.Fatal("kaynak boş")
	}
	if runtime.GOOS == "windows" && got != lockSourceWindow {
		t.Fatalf("aynı programın isteği = %q, want %q", got, lockSourceWindow)
	}

	r := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/login", nil)
	if s := srv.loginSource(r); s != lockSourceUnknown {
		t.Fatalf("çözülemeyen bağlantı = %q, want %q", s, lockSourceUnknown)
	}
}
