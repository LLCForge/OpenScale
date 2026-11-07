//go:build windows

package filesend

import (
	"os"
	"strings"
	"time"
)

func markQuarantine(path, origin string, _ time.Time) error {
	f, err := os.OpenFile(path+":Zone.Identifier", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return ErrQuarantineUnsupported
	}
	text := "[ZoneTransfer]\r\nZoneId=3\r\n"
	if origin != "" {
		text += "ReferrerUrl=" + origin + "\r\n"
	}
	_, werr := f.WriteString(text)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func isQuarantined(path string) bool {
	b, err := os.ReadFile(path + ":Zone.Identifier")
	if err != nil || len(b) > 4096 {
		return false
	}
	return strings.Contains(string(b), "ZoneId=3") || strings.Contains(string(b), "ZoneId=4")
}
