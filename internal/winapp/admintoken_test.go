package winapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/piv"
)

type fakeChecker struct {
	res piv.PresenceResult
	err error
}

func (f *fakeChecker) Check(context.Context) (piv.PresenceResult, error) { return f.res, f.err }

type fakeSessionAPI struct {
	opens   int
	closes  []string
	openErr error
}

func (f *fakeSessionAPI) OpenTokenSession(context.Context, piv.PresenceResult) error {
	f.opens++
	return f.openErr
}

func (f *fakeSessionAPI) CloseTokenSession(_ context.Context, reason string) error {
	f.closes = append(f.closes, reason)
	return nil
}

var (
	adminCard = piv.PresenceResult{Present: true, Reader: "Yubico YubiKey", Match: 0}
	otherCard = piv.PresenceResult{Present: true, Reader: "Yubico YubiKey", Match: -1}
	noCard    = piv.PresenceResult{Match: -1}
)

func newWatcher() (*AdminTokenWatcher, *fakeChecker, *fakeSessionAPI, *time.Time) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	c := &fakeChecker{res: noCard}
	api := &fakeSessionAPI{}
	w := &AdminTokenWatcher{Checker: c, API: api, Now: func() time.Time { return now }}
	return w, c, api, &now
}

func TestAdminTokenInsertAndRemove(t *testing.T) {
	w, c, api, _ := newWatcher()
	ctx := context.Background()
	var changes int
	w.OnChange = func(AdminTokenState) { changes++ }
	if s := w.Step(ctx); s.SessionOpen || s.Admin {
		t.Fatalf("no card: %+v", s)
	}
	c.res = otherCard
	if s := w.Step(ctx); s.SessionOpen || !s.Present || api.opens != 0 {
		t.Fatalf("foreign card opened a session: %+v", s)
	}
	c.res = adminCard
	s := w.Step(ctx)
	if !s.SessionOpen || api.opens != 1 || s.Message == "" {
		t.Fatalf("insert: %+v opens=%d", s, api.opens)
	}
	// Still inserted: no second open.
	w.Step(ctx)
	if api.opens != 1 {
		t.Fatalf("reopened: %d", api.opens)
	}
	c.res = noCard
	if s := w.Step(ctx); s.SessionOpen || len(api.closes) != 1 || api.closes[0] != ReasonTokenRemoved {
		t.Fatalf("remove: %+v %v", s, api.closes)
	}
	if changes < 3 {
		t.Fatalf("changes = %d", changes)
	}
}

func TestAdminTokenSessionLimit(t *testing.T) {
	w, c, api, now := newWatcher()
	ctx := context.Background()
	c.res = adminCard
	w.Step(ctx)
	*now = now.Add(DefaultTokenMaxSession)
	if s := w.Step(ctx); s.SessionOpen || len(api.closes) != 1 || api.closes[0] != ReasonSessionLimit {
		t.Fatalf("limit: %+v %v", s, api.closes)
	}
	// The token stays in: no new session until it is removed.
	w.Step(ctx)
	if api.opens != 1 {
		t.Fatalf("session reopened without removal: %d", api.opens)
	}
	c.res = noCard
	w.Step(ctx)
	c.res = adminCard
	if s := w.Step(ctx); !s.SessionOpen || api.opens != 2 {
		t.Fatalf("reinsert: %+v opens=%d", s, api.opens)
	}
}

func TestAdminTokenRefusedAndReaderError(t *testing.T) {
	w, c, api, _ := newWatcher()
	ctx := context.Background()
	api.openErr = errors.New("imza doğrulanmadı")
	c.res = adminCard
	if s := w.Step(ctx); s.SessionOpen || s.Err == "" {
		t.Fatalf("refused: %+v", s)
	}
	w.Step(ctx)
	if api.opens != 1 {
		t.Fatal("refused insertion retried in a loop")
	}
	api.openErr = nil
	c.res = noCard
	w.Step(ctx)
	c.res = adminCard
	w.Step(ctx)
	if !w.State().SessionOpen {
		t.Fatal("reinsert after refusal")
	}
	// A reader error closes the session (fail closed).
	c.err = errors.New("SCardListReaders")
	if s := w.Step(ctx); s.SessionOpen || s.Err == "" {
		t.Fatalf("reader error: %+v", s)
	}
}

func TestAdminTokenRunClosesOnStop(t *testing.T) {
	w, c, api, _ := newWatcher()
	c.res = adminCard
	w.Poll = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !w.State().SessionOpen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(api.closes) == 0 || api.closes[len(api.closes)-1] != ReasonStopped {
		t.Fatalf("closes = %v", api.closes)
	}
	if err := (&AdminTokenWatcher{}).Run(context.Background()); !errors.Is(err, ErrNoChecker) {
		t.Fatal(err)
	}
}
