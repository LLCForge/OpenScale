package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestLoginInfoLocalAndRemote(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	rec := do(t, h, http.MethodGet, "/api/login-info", nil, nil)
	var got loginInfo
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Remote {
		t.Fatalf("local login-info = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/login-info", nil, func(r *http.Request) {
		*r = *r.WithContext(context.WithValue(r.Context(), remoteCtxKey{}, "laptop"))
	})
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !got.Remote {
		t.Fatalf("remote login-info = %d %s", rec.Code, rec.Body.String())
	}
	req, _ := http.NewRequest(http.MethodGet, "/api/login-info", nil)
	if !remoteAllowed(req) {
		t.Fatal("login-info must be readable remotely")
	}
}

func TestWave3NeedSession(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	for _, p := range []string{"/api/network/coordinators", "/api/security/approval", "/api/app/exit-auto"} {
		if rec := do(t, h, http.MethodGet, p, nil, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without session = %d", p, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/profile", map[string]string{"name": "aile"}, nil); rec.Code == http.StatusOK {
		t.Fatal("tray profile switch without the app token must fail")
	}
}
