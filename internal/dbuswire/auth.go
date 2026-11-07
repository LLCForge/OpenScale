package dbuswire

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxAuthLine bounds one line of the authentication exchange.
const maxAuthLine = 512

// ErrAuth: the bus refused authentication or answered outside the
// protocol.
var ErrAuth = errors.New("dbus: kimlik doğrulama başarısız")

// authResult is what the authentication exchange learned.
type authResult struct {
	guid string
	// unixFD: the bus agreed to pass file descriptors.
	unixFD bool
}

// authenticate runs SASL EXTERNAL with uid (decimal, as the bus expects)
// and, when wantFD is set, NEGOTIATE_UNIX_FD. Only the replies OK, DATA,
// REJECTED, AGREE_UNIX_FD and ERROR are understood; anything else ends
// the connection. r must be the reader the messages are read from
// afterwards (the bus may send the first message right after BEGIN).
func authenticate(w io.Writer, r *bufio.Reader, uid string, wantFD bool) (authResult, error) {
	var res authResult
	if uid == "" || strings.IndexFunc(uid, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
		return res, fmt.Errorf("%w: EXTERNAL için Unix kullanıcı kimliği yok", ErrAuth)
	}
	// The first byte must be NUL (credentials pass with it on Unix).
	if _, err := w.Write([]byte{0}); err != nil {
		return res, err
	}
	if err := writeLine(w, "AUTH EXTERNAL "+hex.EncodeToString([]byte(uid))); err != nil {
		return res, err
	}
	for step := 0; ; step++ {
		if step > 4 {
			return res, fmt.Errorf("%w: çok fazla adım", ErrAuth)
		}
		line, err := readAuthLine(r)
		if err != nil {
			return res, err
		}
		cmd, arg, _ := strings.Cut(line, " ")
		switch cmd {
		case "OK":
			if arg == "" || len(arg) != 32 {
				return res, fmt.Errorf("%w: sunucu kimliği geçersiz", ErrAuth)
			}
			if _, err := hex.DecodeString(arg); err != nil {
				return res, fmt.Errorf("%w: sunucu kimliği geçersiz", ErrAuth)
			}
			res.guid = arg
			if wantFD {
				if err := writeLine(w, "NEGOTIATE_UNIX_FD"); err != nil {
					return res, err
				}
				reply, err := readAuthLine(r)
				if err != nil {
					return res, err
				}
				switch {
				case reply == "AGREE_UNIX_FD":
					res.unixFD = true
				case strings.HasPrefix(reply, "ERROR"):
				default:
					return res, fmt.Errorf("%w: beklenmeyen yanıt", ErrAuth)
				}
			}
			if err := writeLine(w, "BEGIN"); err != nil {
				return res, err
			}
			return res, nil
		case "DATA":
			// EXTERNAL has nothing more to say: an empty response.
			if err := writeLine(w, "DATA"); err != nil {
				return res, err
			}
		case "REJECTED":
			return res, fmt.Errorf("%w: EXTERNAL reddedildi", ErrAuth)
		case "ERROR":
			_ = writeLine(w, "CANCEL")
			return res, fmt.Errorf("%w: sunucu hata bildirdi", ErrAuth)
		default:
			return res, fmt.Errorf("%w: beklenmeyen yanıt", ErrAuth)
		}
	}
}

func writeLine(w io.Writer, s string) error {
	_, err := io.WriteString(w, s+"\r\n")
	return err
}

// readAuthLine reads one CRLF-terminated ASCII line of at most
// maxAuthLine bytes.
func readAuthLine(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
		if c == '\n' {
			break
		}
		if len(b) >= maxAuthLine {
			return "", fmt.Errorf("%w: satır çok uzun", ErrAuth)
		}
		if c < 0x20 && c != '\r' || c > 0x7e {
			return "", fmt.Errorf("%w: ASCII olmayan yanıt", ErrAuth)
		}
		b = append(b, c)
	}
	s := string(b)
	if !strings.HasSuffix(s, "\r") {
		return "", fmt.Errorf("%w: satır CRLF ile bitmiyor", ErrAuth)
	}
	return strings.TrimSuffix(s, "\r"), nil
}
