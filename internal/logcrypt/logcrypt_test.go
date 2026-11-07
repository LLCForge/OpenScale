package logcrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestRoundTrip(t *testing.T) {
	var file bytes.Buffer
	w, err := NewWriter(&file, seed(1), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"time=1 level=DEBUG msg=start\n", "time=2 level=DEBUG msg=peer endpoint=10.0.0.1\n", ""}
	for _, l := range lines {
		if _, err := w.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(file.Bytes(), []byte("endpoint")) {
		t.Fatal("plaintext on disk")
	}
	var out bytes.Buffer
	n, err := Decrypt(&out, bytes.NewReader(file.Bytes()), seed(1))
	if err != nil || n != len(lines) {
		t.Fatalf("decrypt %d %v", n, err)
	}
	if out.String() != strings.Join(lines, "") {
		t.Fatalf("got %q", out.String())
	}
	if _, err := Decrypt(io.Discard, bytes.NewReader(file.Bytes()), seed(2)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Decrypt(io.Discard, strings.NewReader("plain text log"), seed(1)); !errors.Is(err, ErrNotEncryptedLog) {
		t.Fatalf("plain file: %v", err)
	}
}

func TestTamperAndReorder(t *testing.T) {
	var file bytes.Buffer
	w, _ := NewWriter(&file, seed(1), rand.Reader)
	_, _ = w.Write([]byte("first"))
	_, _ = w.Write([]byte("second"))
	data := file.Bytes()
	rec := 4 + 5 + 16
	// Swap the two records.
	swapped := append([]byte(nil), data[:HeaderSize]...)
	swapped = append(swapped, data[HeaderSize+rec:]...)
	swapped = append(swapped, data[HeaderSize:HeaderSize+rec]...)
	if _, err := Decrypt(io.Discard, bytes.NewReader(swapped), seed(1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reordered: %v", err)
	}
	flipped := append([]byte(nil), data...)
	flipped[HeaderSize+6] ^= 1
	if _, err := Decrypt(io.Discard, bytes.NewReader(flipped), seed(1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("flipped: %v", err)
	}
	// Truncation at a record boundary is accepted, inside a record is not.
	if n, err := Decrypt(io.Discard, bytes.NewReader(data[:HeaderSize+rec]), seed(1)); err != nil || n != 1 {
		t.Fatalf("boundary truncation %d %v", n, err)
	}
	if _, err := Decrypt(io.Discard, bytes.NewReader(data[:len(data)-3]), seed(1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("partial record: %v", err)
	}
	if _, err := NewWriter(io.Discard, []byte("short"), rand.Reader); err == nil {
		t.Fatal("short seed accepted")
	}
}

func FuzzReader(f *testing.F) {
	var file bytes.Buffer
	w, _ := NewWriter(&file, seed(3), rand.Reader)
	_, _ = w.Write([]byte("hello"))
	f.Add(file.Bytes())
	f.Add([]byte(magic + "0123456789abcdef\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decrypt(io.Discard, bytes.NewReader(data), seed(3))
	})
}
