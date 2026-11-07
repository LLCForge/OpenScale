package privsep

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/trust"
)

// helperMemoryLimit is the helper's soft heap limit; the frames it reads
// are at most maxFrame, so a parser that needs far more is misbehaving.
const helperMemoryLimit = 256 << 20

// HelperOptions change how RunHelper starts. The program's entry point
// passes the zero value.
type HelperOptions struct {
	// SkipConfine runs without dropping rights or entering the sandbox.
	// Only tests set it, to run the protocol in an ordinary child process.
	SkipConfine bool
}

// RunHelper is the helper process: it checks it runs without rights,
// enters the sandbox, announces itself and serves requests on standard
// input and output until the parent closes the pipe. It returns the exit
// code.
func RunHelper(opts HelperOptions) int {
	debug.SetMemoryLimit(helperMemoryLimit)
	summary := "sınırlama atlandı (test)"
	if !opts.SkipConfine {
		if err := Enter(); err != nil {
			fmt.Fprintln(os.Stderr, "openscale ayrıştırma yardımcısı:", err)
			return 3
		}
		summary = confine()
	}
	if err := Serve(os.Stdin, os.Stdout, summary); err != nil {
		fmt.Fprintln(os.Stderr, "openscale ayrıştırma yardımcısı:", err)
		return 2
	}
	return 0
}

// Serve announces the helper and answers requests until r ends. A request
// it cannot read ends the helper: the parent rejects the document and
// starts a fresh helper next time.
func Serve(r io.Reader, w io.Writer, summary string) error {
	in := bufio.NewReaderSize(r, 64<<10)
	out := bufio.NewWriterSize(w, 64<<10)
	if err := writeFrame(out, statusHello, []byte(helperMagic+"\n"+summary)); err != nil {
		return err
	}
	if err := out.Flush(); err != nil {
		return err
	}
	for {
		tag, data, err := readFrame(in)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		reply, fatal, perr := parseSafely(Kind(tag), data)
		status := statusOK
		if perr != nil {
			status, reply = statusReject, []byte(reason(perr))
		}
		if err := writeFrame(out, status, reply); err != nil {
			return err
		}
		if err := out.Flush(); err != nil {
			return err
		}
		if fatal {
			return errors.New("ayrıştırıcı çöktü; yardımcı kapanıyor")
		}
	}
}

// parseSafely runs one parser; a panic rejects the input and ends the
// helper, whose state may no longer be sound.
func parseSafely(kind Kind, data []byte) (reply []byte, fatal bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			reply, fatal, err = nil, true, errors.New("ayrıştırıcı hata verdi")
		}
	}()
	reply, err = Parse(kind, data)
	return reply, false, err
}

// Parse is what the helper does with one request. It runs in the parent
// too when the helper is off (ModeOff) or not available (ModeAuto).
func Parse(kind Kind, data []byte) ([]byte, error) {
	switch kind {
	case KindEnvelope:
		// Pre-authentication parse of an untrusted envelope, including the
		// nested envelopes and cosignatures UnmarshalEnvelope checks. The
		// canonical re-encoding is what the parent's store parses next:
		// attacker-chosen JSON never reaches the privileged process.
		env, err := trust.UnmarshalEnvelope(data)
		if err != nil {
			return nil, err
		}
		return trust.MarshalEnvelope(env)
	case KindRelease:
		if _, err := release.UnmarshalEnvelope(data); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return nil, fmt.Errorf("bilinmeyen istek türü %d", byte(kind))
}

// reason shortens an error for the reply.
func reason(err error) string {
	s := err.Error()
	if len(s) > maxReason {
		s = s[:maxReason]
	}
	return strings.ToValidUTF8(s, "?")
}
