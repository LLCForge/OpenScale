package filesend

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Local antivirus scan of received files (#458). The file is handed to
// the scanner already installed on this computer: Microsoft Defender's
// command line tool on Windows, ClamAV's clamscan elsewhere. OpenScale
// sends nothing anywhere; the scanner runs with remediation off and only
// reports. Defender may submit samples to Microsoft when its cloud
// protection is on; CloudNote says so (or that it could not tell).

// Scan verdicts.
const (
	VerdictClean       = "clean"
	VerdictInfected    = "infected"
	VerdictError       = "error"
	VerdictUnavailable = "unavailable"
)

const (
	scanTimeout   = 5 * time.Minute
	maxScanOutput = 16 << 10
)

// ScanResult is the outcome of one scan.
type ScanResult struct {
	Scanner string    `json:"scanner"`
	Verdict string    `json:"verdict"`
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
	// CloudNote is set when the scanner may contact its vendor.
	CloudNote string `json:"cloud_note,omitempty"`
}

// Scanner is a local antivirus command line tool.
type Scanner struct {
	// Kind is "defender" or "clamav".
	Kind string
	// Path is the tool's absolute path.
	Path string
	// prefix is put before the arguments (tests run a helper process).
	prefix []string
	// cloud reports Defender's cloud protection (tests replace it).
	cloud func() (on, known bool)
}

// FindScanner looks for an installed scanner.
func FindScanner() (Scanner, bool) {
	if runtime.GOOS == "windows" {
		for _, env := range []string{"ProgramFiles", "ProgramW6432"} {
			base := os.Getenv(env)
			if base == "" || !filepath.IsAbs(base) {
				continue
			}
			p := filepath.Join(base, "Windows Defender", "MpCmdRun.exe")
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				return Scanner{Kind: "defender", Path: p, cloud: defenderCloud}, true
			}
		}
		return Scanner{}, false
	}
	for _, name := range []string{"clamdscan", "clamscan"} {
		if p, err := exec.LookPath(name); err == nil && filepath.IsAbs(p) {
			return Scanner{Kind: "clamav", Path: p}, true
		}
	}
	return Scanner{}, false
}

// Name is the scanner's display name.
func (s Scanner) Name() string {
	switch s.Kind {
	case "defender":
		return "Microsoft Defender"
	case "clamav":
		return "ClamAV"
	}
	return s.Kind
}

// CloudNote explains whether the scanner may send data to its vendor.
func (s Scanner) CloudNote() string {
	if s.Kind != "defender" {
		return ""
	}
	cloud := s.cloud
	if cloud == nil {
		cloud = defenderCloud
	}
	on, known := cloud()
	switch {
	case !known:
		return "Defender bulut korumasının durumu okunamadı; açıksa Defender şüpheli dosyadan örneği Microsoft'a gönderebilir."
	case on:
		return "Defender bulut koruması açık: Defender şüpheli dosyanın örneğini Microsoft'a gönderebilir. Bunu OpenScale değil Windows ayarları belirler."
	}
	return ""
}

// Scan scans one file. The scanner runs without a shell, with the file
// path as a separate argument.
func (s Scanner) Scan(ctx context.Context, file string) ScanResult {
	res := ScanResult{Scanner: s.Name(), At: time.Now().UTC(), CloudNote: s.CloudNote()}
	if s.Path == "" || !filepath.IsAbs(file) {
		res.Verdict, res.Detail = VerdictUnavailable, "yerel antivirüs bulunamadı"
		return res
	}
	var args []string
	switch s.Kind {
	case "defender":
		args = []string{"-Scan", "-ScanType", "3", "-File", file, "-DisableRemediation"}
	case "clamav":
		args = []string{"--no-summary", "--stdout", "--", file}
	default:
		res.Verdict, res.Detail = VerdictUnavailable, "bilinmeyen antivirüs"
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Path, append(append([]string{}, s.prefix...), args...)...)
	var out limitedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		res.Verdict, res.Detail = VerdictError, "antivirüs çalıştırılamadı"
		return res
	}
	if ctx.Err() != nil {
		res.Verdict, res.Detail = VerdictError, "tarama zaman aşımına uğradı"
		return res
	}
	switch {
	case code == 0:
		res.Verdict = VerdictClean
	case (s.Kind == "defender" && code == 2) || (s.Kind == "clamav" && code == 1):
		res.Verdict, res.Detail = VerdictInfected, threatName(s.Kind, out.String())
	default:
		res.Verdict, res.Detail = VerdictError, "antivirüs hata kodu döndürdü"
	}
	return res
}

// threatName picks the detection name from the scanner's output.
func threatName(kind, out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch kind {
		case "clamav":
			if rest, ok := strings.CutSuffix(line, " FOUND"); ok {
				if i := strings.LastIndex(rest, ": "); i >= 0 {
					return clip(rest[i+2:])
				}
			}
		case "defender":
			if rest, ok := strings.CutPrefix(line, "Threat "); ok {
				if i := strings.Index(rest, ":"); i >= 0 {
					return clip(strings.TrimSpace(rest[i+1:]))
				}
			}
		}
	}
	return "tehdit bulundu"
}

func clip(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// limitedBuffer keeps the first maxScanOutput bytes.
type limitedBuffer struct{ b bytes.Buffer }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxScanOutput - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }
