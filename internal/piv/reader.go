package piv

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// defaultReaderSubstring picks YubiKey readers; their PC/SC names start with
// "Yubico YubiKey" on Windows, Linux (pcsclite CCID) and macOS.
const defaultReaderSubstring = "yubico"

// pickReader chooses a reader: an exact (case-insensitive) name first,
// otherwise the first name containing want.
func pickReader(readers []string, want string) (string, error) {
	if len(readers) == 0 {
		return "", errors.New("no smart card reader found")
	}
	if want == "" {
		want = defaultReaderSubstring
	}
	want = strings.ToLower(want)
	for _, r := range readers {
		if strings.ToLower(r) == want {
			return r, nil
		}
	}
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), want) {
			return r, nil
		}
	}
	return "", fmt.Errorf("no reader matches %q (found: %s)", want, strings.Join(readers, ", "))
}

// matchingReaders returns the readers whose name contains want (default
// "yubico"), in order, at most 8.
func matchingReaders(readers []string, want string) []string {
	if want == "" {
		want = defaultReaderSubstring
	}
	want = strings.ToLower(want)
	var out []string
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), want) {
			out = append(out, r)
			if len(out) == 8 {
				break
			}
		}
	}
	return out
}

// pollReaderChange is the portable WaitReaderChange: it lists the readers
// every interval until the list differs from the first one, timeout passes
// or ctx ends. Listing readers sends nothing to a card.
func pollReaderChange(ctx context.Context, timeout, interval time.Duration) (bool, error) {
	first, err := Readers()
	if err != nil && !errors.Is(err, ErrUnsupported) {
		first = nil
	} else if err != nil {
		return false, err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline.C:
			return false, nil
		case <-tick.C:
			now, err := Readers()
			if err != nil {
				now = nil
			}
			if !slices.Equal(now, first) {
				return true, nil
			}
		}
	}
}
