package privacy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func randomKey(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func TestMaskAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.45":   "203.0.*.*",
		"100.80.0.7":     "100.80.*.*",
		"2001:db8:1::5":  "2001:db8:*",
		"127.0.0.1":      "127.0.0.1",
		"::1":            "::1",
		"0.0.0.0":        "0.0.0.0",
		"::ffff:8.8.4.4": "8.8.*.*",
	}
	for in, want := range cases {
		if got := MaskAddr(netip.MustParseAddr(in)); got != want {
			t.Errorf("MaskAddr(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskText(t *testing.T) {
	cases := map[string]string{
		"dial udp 198.51.100.9:51820: i/o timeout":     "dial udp 198.51.*.*:51820: i/o timeout",
		"peer at [2001:db8::42]:41641 ok":              "peer at [2001:db8:*]:41641 ok",
		"addr 2001:db8::1: refused":                    "addr 2001:db8:*: refused",
		"at 12:30:45 nothing":                          "at 12:30:45 nothing",
		"mac aa:bb:cc:dd:ee:ff stays":                  "mac aa:bb:cc:dd:ee:ff stays",
		"listening on 127.0.0.1:47821":                 "listening on 127.0.0.1:47821",
		"two 10.0.0.1 and 192.168.1.20":                "two 10.0.*.* and 192.168.*.*",
		"version 1.2.3 is not an address":              "version 1.2.3 is not an address",
		"link-local fe80::1%eth0 hidden":               "link-local fe80:0:* hidden",
		"no addresses here, only device laptop-1 here": "no addresses here, only device laptop-1 here",
	}
	for in, want := range cases {
		if got := MaskText(in); got != want {
			t.Errorf("MaskText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskTextBounded(t *testing.T) {
	long := strings.Repeat("a", maxMaskedLen*2)
	if got := MaskText(long); len(got) > maxMaskedLen+8 {
		t.Fatalf("masked text not bounded: %d bytes", len(got))
	}
}

func TestIsSecretKey(t *testing.T) {
	for _, k := range []string{"private_key", "PrivateKey", "token", "app.token", "passphrase", "psk", "root_key", "bundle", "Authorization"} {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false", k)
		}
	}
	for _, k := range []string{"device", "peer", "endpoint", "error", "version", "msg"} {
		if IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = true", k)
		}
	}
}

// logAt logs through the masking handler at the given minimum level and
// returns the JSON output.
func logAt(t *testing.T, level slog.Level, fn func(*slog.Logger)) string {
	t.Helper()
	var buf bytes.Buffer
	l := NewMaskedLogger(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level}))
	fn(l)
	return buf.String()
}

// TestLogNeverContainsKeys is the #42 rule "anahtarlar hiçbir seviyede
// yazılmaz": a key given under a secret name, inside a message, in an
// error or in a nested group never reaches the output.
func TestLogNeverContainsKeys(t *testing.T) {
	key := randomKey(t)
	for _, lvl := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		out := logAt(t, slog.LevelDebug, func(l *slog.Logger) {
			l.Log(t.Context(), lvl, "loaded "+key,
				"private_key", key,
				"note", "wg key "+key,
				"error", errors.New("bad key "+key),
				slog.Group("peer", "psk", key, "raw", []byte(key)),
				"pem", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
			)
			l.With("token", "s3cr3t-token-value").Log(t.Context(), lvl, "bound")
		})
		if strings.Contains(out, key) || strings.Contains(out, "s3cr3t-token-value") || strings.Contains(out, "BEGIN PRIVATE") {
			t.Fatalf("level %v leaked a secret:\n%s", lvl, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Fatalf("level %v: no redaction marker:\n%s", lvl, out)
		}
	}
}

// TestLogMasksAddressesFromInfo is the #42 rule "info ve üzeri loglarda IP
// adresleri maskelenir"; debug keeps them (ADR-0008).
func TestLogMasksAddressesFromInfo(t *testing.T) {
	const public = "198.51.100.77"
	const v6 = "2001:db8:aa::77"
	emit := func(l *slog.Logger, lvl slog.Level) {
		l.Log(t.Context(), lvl, "peer endpoint "+public+":51820",
			"endpoint", public+":51820",
			"addr", netip.MustParseAddr(v6),
			"ap", netip.MustParseAddrPort("["+v6+"]:9"),
			"error", errors.New("read udp "+public+":1: closed"),
			slog.Group("g", "remote", public),
		)
	}
	for _, lvl := range []slog.Level{slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		out := logAt(t, slog.LevelDebug, func(l *slog.Logger) { emit(l, lvl) })
		if strings.Contains(out, public) || strings.Contains(out, v6) || strings.Contains(out, "100.77") {
			t.Fatalf("level %v leaked an address:\n%s", lvl, out)
		}
		if !strings.Contains(out, "198.51.*.*") {
			t.Fatalf("level %v: masked form missing:\n%s", lvl, out)
		}
	}
	out := logAt(t, slog.LevelDebug, func(l *slog.Logger) { emit(l, slog.LevelDebug) })
	if !strings.Contains(out, public) {
		t.Fatalf("debug lost the address the owner asked for:\n%s", out)
	}
	// Attributes bound with With are masked at every level.
	out = logAt(t, slog.LevelDebug, func(l *slog.Logger) { l.With("coord", public).Debug("x") })
	if strings.Contains(out, public) {
		t.Fatalf("bound attribute leaked an address:\n%s", out)
	}
}

func TestHandlerPassesLevelAndGroups(t *testing.T) {
	var buf bytes.Buffer
	l := NewMaskedLogger(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	l.Info("hidden")
	l.WithGroup("svc").Warn("shown", "n", 3)
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, `"svc":{"n":3}`) {
		t.Fatalf("unexpected output: %s", out)
	}
}
