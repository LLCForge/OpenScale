package privsep

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Mode chooses whether parsing goes through the helper (ADR-0233).
type Mode int

const (
	// ModeAuto (default) parses through the helper. When the helper cannot
	// be started at all (an unsupported system, no unprivileged account)
	// the parent keeps its old behaviour and says so in the log and the
	// status; once a helper ran, its failures reject the input.
	ModeAuto Mode = iota
	// ModeRequired rejects every input while no helper runs.
	ModeRequired
	// ModeOff never starts a helper (the behaviour before ADR-0233).
	ModeOff
)

// ParseMode accepts "auto" (or ""), "required" and "off".
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ModeAuto, nil
	case "required":
		return ModeRequired, nil
	case "off":
		return ModeOff, nil
	}
	return 0, fmt.Errorf("ayrıştırma yardımcısı kipi %q geçersiz; auto, required veya off yazın", s)
}

func (m Mode) String() string {
	switch m {
	case ModeRequired:
		return "required"
	case ModeOff:
		return "off"
	}
	return "auto"
}

const (
	// defaultTimeout bounds one request; a helper that takes longer is
	// killed and the input rejected.
	defaultTimeout = 10 * time.Second
	// helloTimeout bounds the helper's start.
	helloTimeout = 5 * time.Second
	// restartBackoff is the shortest wait before a failed start is retried.
	restartBackoff = 30 * time.Second
)

// ErrHelperUnavailable rejects input in ModeRequired while no helper runs.
var ErrHelperUnavailable = errors.New("ayrıştırma yardımcısı çalışmıyor; girdi reddedildi")

// GateConfig configures a Gate.
type GateConfig struct {
	Mode Mode
	// Exe is the program started as the helper; "" is this program.
	Exe string
	// Timeout bounds one request; zero is ten seconds.
	Timeout time.Duration
	Logger  *slog.Logger
	// start replaces the process start in tests.
	start func(ctx context.Context) (*helperProc, error)
}

// GateStatus is what diagnostics show.
type GateStatus struct {
	Mode     string `json:"mode"`
	Running  bool   `json:"running"`
	Fallback bool   `json:"fallback"`
	Sandbox  string `json:"sandbox,omitempty"`
	Rejected uint64 `json:"rejected"`
	Restarts uint64 `json:"restarts"`
}

// Gate sends input to the helper and returns its verdict. It is safe for
// concurrent use; requests are served one at a time.
type Gate struct {
	cfg GateConfig

	mu       sync.Mutex
	proc     *helperProc
	failedAt time.Time
	fallback bool
	warned   bool
	sandbox  string
	rejected uint64
	restarts uint64
}

// NewGate returns a gate; the helper starts on the first request.
func NewGate(cfg GateConfig) *Gate {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.start == nil {
		exe := cfg.Exe
		cfg.start = func(ctx context.Context) (*helperProc, error) { return startHelper(ctx, exe) }
	}
	return &Gate{cfg: cfg}
}

// SanitizeEnvelope parses a network document envelope in the helper and
// returns the canonical bytes to accept, or an error that rejects it.
func (g *Gate) SanitizeEnvelope(ctx context.Context, data []byte) ([]byte, error) {
	out, passthrough, err := g.do(ctx, KindEnvelope, data)
	if passthrough {
		return data, nil
	}
	return out, err
}

// CheckRelease parses a signed release manifest in the helper; the caller
// verifies its own bytes afterwards.
func (g *Gate) CheckRelease(ctx context.Context, data []byte) error {
	_, _, err := g.do(ctx, KindRelease, data)
	return err
}

// Status reports the gate's state.
func (g *Gate) Status() GateStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return GateStatus{Mode: g.cfg.Mode.String(), Running: g.proc != nil && g.proc.alive(), Fallback: g.fallback, Sandbox: g.sandbox,
		Rejected: g.rejected, Restarts: g.restarts}
}

// Close stops the helper.
func (g *Gate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.proc != nil {
		g.proc.kill()
		g.proc = nil
	}
	return nil
}

// do runs one request. passthrough means no helper is used (ModeOff, or
// ModeAuto after the helper could not start): the caller keeps its input.
func (g *Gate) do(ctx context.Context, kind Kind, data []byte) (out []byte, passthrough bool, err error) {
	if g.cfg.Mode == ModeOff {
		return nil, true, nil
	}
	if len(data)+1 > maxFrame {
		return nil, false, g.reject(fmt.Errorf("%s çok büyük", kind))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.proc != nil && !g.proc.alive() {
		g.proc.kill()
		g.proc = nil
	}
	if g.proc == nil {
		if !g.failedAt.IsZero() && time.Since(g.failedAt) < restartBackoff {
			return g.unavailableLocked(nil)
		}
		p, err := g.cfg.start(ctx)
		if err != nil {
			g.failedAt = time.Now()
			return g.unavailableLocked(err)
		}
		g.proc, g.failedAt, g.fallback, g.sandbox = p, time.Time{}, false, p.summary
		g.restarts++
		g.cfg.Logger.Info("parsing helper started", "sandbox", p.summary)
	}
	status, reply, err := g.proc.call(ctx, g.cfg.Timeout, kind, data)
	if err != nil {
		// Crash, timeout or a broken reply: the input is rejected and the
		// helper replaced next time (fail closed).
		g.proc.kill()
		g.proc = nil
		g.rejected++
		g.cfg.Logger.Warn("parsing helper failed; input rejected", "kind", kind.String(), "error", err.Error())
		return nil, false, fmt.Errorf("ayrıştırma yardımcısı yanıt vermedi: %w", err)
	}
	if status != statusOK {
		g.rejected++
		return nil, false, fmt.Errorf("%s reddedildi: %s", kind, strings.ToValidUTF8(string(reply), "?"))
	}
	return reply, false, nil
}

func (g *Gate) reject(err error) error {
	g.mu.Lock()
	g.rejected++
	g.mu.Unlock()
	return err
}

// unavailableLocked handles a helper that cannot run.
func (g *Gate) unavailableLocked(startErr error) ([]byte, bool, error) {
	if g.cfg.Mode == ModeRequired {
		g.rejected++
		if startErr != nil {
			g.cfg.Logger.Warn("parsing helper did not start; input rejected", "error", startErr.Error())
		}
		return nil, false, ErrHelperUnavailable
	}
	g.fallback = true
	if startErr != nil && !g.warned {
		g.warned = true
		g.cfg.Logger.Warn("parsing helper unavailable; parsing in this process as before", "error", startErr.Error())
	}
	return nil, true, nil
}

// helperProc is one running helper.
type helperProc struct {
	in      io.WriteCloser
	out     *bufio.Reader
	summary string
	stop    func()
	done    chan struct{}
}

func (p *helperProc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *helperProc) kill() {
	_ = p.in.Close()
	p.stop()
}

type callResult struct {
	status byte
	data   []byte
	err    error
}

// call sends one request and waits for the reply within timeout.
func (p *helperProc) call(ctx context.Context, timeout time.Duration, kind Kind, data []byte) (byte, []byte, error) {
	res := make(chan callResult, 1)
	go func() {
		if err := writeFrame(p.in, byte(kind), data); err != nil {
			res <- callResult{err: err}
			return
		}
		status, reply, err := readFrame(p.out)
		if err == nil && status != statusOK && status != statusReject {
			err = errFrame
		}
		res <- callResult{status: status, data: reply, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-res:
		return r.status, r.data, r.err
	case <-timer.C:
		p.kill() // unblocks the goroutine
		return 0, nil, errors.New("zaman aşımı")
	case <-ctx.Done():
		p.kill()
		return 0, nil, ctx.Err()
	case <-p.done:
		return 0, nil, errors.New("yardımcı süreç kapandı")
	}
}

// newHelperProc wraps pipes to a started helper and waits for its hello.
func newHelperProc(in io.WriteCloser, out io.Reader, stop func(), done chan struct{}) (*helperProc, error) {
	p := &helperProc{in: in, out: bufio.NewReaderSize(out, 64<<10), stop: stop, done: done}
	type hello struct {
		summary string
		err     error
	}
	got := make(chan hello, 1)
	go func() {
		tag, data, err := readFrame(p.out)
		switch {
		case err != nil:
			got <- hello{err: err}
		case tag != statusHello || !strings.HasPrefix(string(data), helperMagic+"\n"):
			got <- hello{err: errors.New("yardımcı tanınmayan bir selam gönderdi")}
		default:
			s := strings.ToValidUTF8(strings.TrimPrefix(string(data), helperMagic+"\n"), "?")
			got <- hello{summary: s[:min(len(s), maxReason)]}
		}
	}()
	timer := time.NewTimer(helloTimeout)
	defer timer.Stop()
	select {
	case h := <-got:
		if h.err != nil {
			p.kill()
			return nil, h.err
		}
		p.summary = h.summary
		return p, nil
	case <-timer.C:
		p.kill()
		return nil, errors.New("yardımcı zamanında başlamadı")
	}
}

// startHelper starts exe as the helper with reduced rights (Command) and,
// where the system offers it, inside a job or similar container (contain).
func startHelper(_ context.Context, exe string) (*helperProc, error) {
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	uid, gid, err := helperAccount()
	if err != nil {
		return nil, err
	}
	cmd, release, err := Command(exe, []string{HelperArg}, uid, gid)
	if err != nil {
		return nil, err
	}
	return startCmd(cmd, release)
}

// startCmd starts a prepared helper command.
func startCmd(cmd *exec.Cmd, release func()) (*helperProc, error) {
	defer release()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil // nothing of the helper reaches the parent's log
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("yardımcı başlatılamadı: %w", err)
	}
	uncontain, err := contain(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("yardımcı sınırlanamadı: %w", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		uncontain()
		close(done)
	}()
	stop := func() { _ = cmd.Process.Kill() }
	return newHelperProc(stdin, stdout, stop, done)
}

var (
	defaultMu   sync.Mutex
	defaultGate *Gate
)

// SetDefault installs the process-wide gate other packages use through
// CheckReleaseDefault (nil removes it).
func SetDefault(g *Gate) {
	defaultMu.Lock()
	defaultGate = g
	defaultMu.Unlock()
}

// Default returns the process-wide gate, or nil.
func Default() *Gate {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	return defaultGate
}

// CheckReleaseDefault parses a release manifest in the default gate's
// helper; without a default gate it does nothing.
func CheckReleaseDefault(ctx context.Context, data []byte) error {
	if g := Default(); g != nil {
		return g.CheckRelease(ctx, data)
	}
	return nil
}
