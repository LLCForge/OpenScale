package privsep

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// TestMain runs the test binary as the helper when it is started with
// HelperArg: unconfined for TestRealHelperProcess, with Enter and the
// sandbox for TestConfinedHelperProcess ("confined").
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperArg {
		confined := len(os.Args) > 2 && os.Args[2] == "confined"
		os.Exit(RunHelper(HelperOptions{SkipConfine: !confined}))
	}
	os.Exit(m.Run())
}

func testEnvelope(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.Sign(priv, trust.DocumentContext, []byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// pipeHelper runs Serve in this process behind pipes; behave may replace
// the helper (a crash, a hang, a liar).
func pipeHelper(behave func(in io.Reader, out io.Writer)) func(context.Context) (*helperProc, error) {
	return func(context.Context) (*helperProc, error) {
		reqR, reqW := io.Pipe()
		repR, repW := io.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			if behave != nil {
				behave(reqR, repW)
			} else {
				_ = Serve(reqR, repW, "test")
			}
			_ = repW.Close()
		}()
		stop := func() {
			_ = reqR.CloseWithError(io.ErrClosedPipe)
			_ = repW.CloseWithError(io.ErrClosedPipe)
		}
		return newHelperProc(reqW, repR, stop, done)
	}
}

func TestGateSanitizesEnvelope(t *testing.T) {
	g := NewGate(GateConfig{start: pipeHelper(nil)})
	defer g.Close()
	data := testEnvelope(t)
	// The same envelope, re-indented and with a duplicate-free but
	// differently spaced form, comes back canonical.
	messy := bytes.ReplaceAll(data, []byte("\n  "), []byte(" "))
	out, err := g.SanitizeEnvelope(context.Background(), messy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("not canonical:\n%s\nwant\n%s", out, data)
	}
	if st := g.Status(); !st.Running || st.Sandbox != "test" || st.Fallback {
		t.Fatalf("status %+v", st)
	}
	// Junk, unknown fields and oversized input are rejected by the helper.
	for _, bad := range [][]byte{[]byte("{"), []byte(`{"context":"x","extra":1}`), bytes.Repeat([]byte(" "), trust.MaxEnvelopeSize+1)} {
		if _, err := g.SanitizeEnvelope(context.Background(), bad); err == nil {
			t.Fatalf("accepted %.40q", bad)
		}
	}
	if st := g.Status(); st.Rejected != 3 || !st.Running {
		t.Fatalf("after rejections %+v", st)
	}
	if err := g.CheckRelease(context.Background(), []byte("not a release")); err == nil {
		t.Fatal("release junk accepted")
	}
}

// A helper that dies, hangs or answers nonsense rejects the input (fail
// closed) and is replaced on the next request.
func TestGateFailsClosed(t *testing.T) {
	data := testEnvelope(t)
	behaviours := map[string]func(in io.Reader, out io.Writer){
		"crash": func(in io.Reader, out io.Writer) {
			_ = writeFrame(out, statusHello, []byte(helperMagic+"\nx"))
			buf := make([]byte, 8)
			_, _ = in.Read(buf) // read part of the request, then die
		},
		"hang": func(in io.Reader, out io.Writer) {
			_ = writeFrame(out, statusHello, []byte(helperMagic+"\nx"))
			_, _ = io.Copy(io.Discard, in)
		},
		"liar": func(in io.Reader, out io.Writer) {
			_ = writeFrame(out, statusHello, []byte(helperMagic+"\nx"))
			_, _ = in.Read(make([]byte, 1<<16))
			_, _ = out.Write([]byte{0xff, 0xff, 0xff, 0xff})
		},
		"bad status": func(in io.Reader, out io.Writer) {
			_ = writeFrame(out, statusHello, []byte(helperMagic+"\nx"))
			_, _ = in.Read(make([]byte, 1<<16))
			_ = writeFrame(out, 9, []byte("ok"))
		},
	}
	for name, behave := range behaviours {
		starts := 0
		inner := pipeHelper(behave)
		g := NewGate(GateConfig{Timeout: 300 * time.Millisecond, start: func(ctx context.Context) (*helperProc, error) {
			starts++
			return inner(ctx)
		}})
		if _, err := g.SanitizeEnvelope(context.Background(), data); err == nil {
			t.Fatalf("%s: input accepted", name)
		}
		if st := g.Status(); st.Running || st.Fallback {
			t.Fatalf("%s: status %+v", name, st)
		}
		// Next request: a fresh helper (it misbehaves again: rejected again).
		if _, err := g.SanitizeEnvelope(context.Background(), data); err == nil || starts != 2 {
			t.Fatalf("%s: second request %v after %d starts", name, err, starts)
		}
		g.Close()
	}
}

func TestGateStartFailure(t *testing.T) {
	data := testEnvelope(t)
	fail := func(context.Context) (*helperProc, error) { return nil, errors.New("no account") }
	auto := NewGate(GateConfig{Mode: ModeAuto, start: fail})
	out, err := auto.SanitizeEnvelope(context.Background(), data)
	if err != nil || !bytes.Equal(out, data) || !auto.Status().Fallback {
		t.Fatalf("auto fallback: %v %+v", err, auto.Status())
	}
	req := NewGate(GateConfig{Mode: ModeRequired, start: fail})
	if _, err := req.SanitizeEnvelope(context.Background(), data); !errors.Is(err, ErrHelperUnavailable) {
		t.Fatalf("required: %v", err)
	}
	// A helper that never says hello is a start failure too.
	silent := pipeHelper(func(in io.Reader, _ io.Writer) { _, _ = io.Copy(io.Discard, in) })
	if _, err := silent(context.Background()); err == nil {
		t.Fatal("silent helper accepted")
	}
	off := NewGate(GateConfig{Mode: ModeOff, start: func(context.Context) (*helperProc, error) {
		t.Fatal("helper started in off mode")
		return nil, nil
	}})
	if out, err := off.SanitizeEnvelope(context.Background(), data); err != nil || !bytes.Equal(out, data) {
		t.Fatal("off mode changed the input")
	}
	for _, s := range []string{"", "auto", "required", "OFF"} {
		m, err := ParseMode(s)
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := ParseMode(m.String()); again != m {
			t.Fatalf("%q round trip", s)
		}
	}
	if _, err := ParseMode("maybe"); err == nil {
		t.Fatal("bad mode accepted")
	}
}

func TestFramesBounded(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, 1, make([]byte, maxFrame)); err == nil {
		t.Fatal("oversized frame written")
	}
	for _, raw := range [][]byte{{0, 0, 0, 0}, {0x7f, 0xff, 0xff, 0xff}, {0, 0, 0, 5, 1}} {
		if _, _, err := readFrame(newReader(raw)); err == nil {
			t.Fatalf("frame %x read", raw)
		}
	}
	// A panicking parser rejects the input and ends the helper.
	_, fatal, err := parseSafely(Kind(0xEE), nil)
	if err == nil || fatal {
		t.Fatalf("unknown kind: %v %v", err, fatal)
	}
	if !strings.Contains(KindEnvelope.String(), "belge") || reason(errors.New(strings.Repeat("ş", 300))) == "" {
		t.Fatal("texts")
	}
}

// The real process path: the test binary started as a helper over pipes,
// without changing rights (TestMain).
func TestRealHelperProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	g := NewGate(GateConfig{Mode: ModeRequired, start: func(context.Context) (*helperProc, error) {
		return startCmd(exec.Command(exe, HelperArg), func() {})
	}})
	defer g.Close()
	data := testEnvelope(t)
	out, err := g.SanitizeEnvelope(context.Background(), data)
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("real helper: %v", err)
	}
	if _, err := g.SanitizeEnvelope(context.Background(), []byte("{")); err == nil {
		t.Fatal("real helper accepted junk")
	}
	if st := g.Status(); !st.Running || st.Restarts != 1 {
		t.Fatalf("status %+v", st)
	}
}

func newReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

// The full path where the system supports it: reduced rights (Command),
// Enter's checks and the sandbox, then the protocol. On Windows the test
// binary is copied to a directory Users may read, as Program Files is.
func TestConfinedHelperProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() == 0 {
			t.Skip("as root the helper would switch to the nobody account, which cannot read the test binary")
		}
	case "windows":
		exe = copyForRestrictedToken(t, exe)
	default:
		t.Skip("no helper isolation on this system")
	}
	g := NewGate(GateConfig{Mode: ModeRequired, start: func(context.Context) (*helperProc, error) {
		cmd, release, err := Command(exe, []string{HelperArg, "confined"}, 0, 0)
		if err != nil {
			return nil, err
		}
		return startCmd(cmd, release)
	}})
	defer g.Close()
	data := testEnvelope(t)
	out, err := g.SanitizeEnvelope(context.Background(), data)
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("confined helper: %v", err)
	}
	if _, err := g.SanitizeEnvelope(context.Background(), []byte(`{"context":1}`)); err == nil {
		t.Fatal("confined helper accepted junk")
	}
	st := g.Status()
	if !st.Running || st.Sandbox == "" || strings.Contains(st.Sandbox, "test") {
		t.Fatalf("status %+v", st)
	}
	t.Logf("sandbox: %s", st.Sandbox)
}

func copyForRestrictedToken(t *testing.T, exe string) string {
	t.Helper()
	dir := t.TempDir()
	dst := filepath.Join(dir, filepath.Base(exe))
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		t.Fatal(err)
	}
	// BUILTIN\Users and RESTRICTED may read and run it.
	if out, err := exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)RX", "*S-1-5-12:(OI)(CI)RX").CombinedOutput(); err != nil {
		t.Skipf("icacls: %v %s", err, out)
	}
	return dst
}
