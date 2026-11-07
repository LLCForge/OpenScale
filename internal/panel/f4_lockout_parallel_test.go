package panel

import (
	"net/http"
	"sync"
	"testing"
)

// The counter is written only after the slow passphrase check, so without a
// reservation parallel requests all pass the lockout check: the budget of
// guesses would be limited by CPU alone.
func TestParallelLoginsCannotExceedLockout(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	srv.g5.desk.lockSource = func(*http.Request) string { return "yerel:S-1-5-21-saldirgan" }

	const attempts = 24
	codes := make([]int, attempts)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": "yanlış parola 123456"}, withOrigin).Code
		}()
	}
	close(start)
	wg.Wait()
	guesses := 0
	for _, c := range codes {
		if c == http.StatusUnauthorized {
			guesses++
		}
	}
	if guesses > lockoutFailures {
		t.Fatalf("%d parola denendi, sınır %d (yanıtlar %v)", guesses, lockoutFailures, codes)
	}

	// Attempts that ended gave their reservation back: only the failures count.
	if rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, withOrigin); guesses < lockoutFailures && rec.Code != http.StatusOK {
		t.Fatalf("rezervasyon geri verilmedi: %d", rec.Code)
	}
}
