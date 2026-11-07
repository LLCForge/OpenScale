package secmem

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewSizeBounds(t *testing.T) {
	for _, n := range []int{0, -1, MaxSize + 1} {
		if _, err := New(n); !errors.Is(err, ErrSize) {
			t.Fatalf("New(%d) = %v, want ErrSize", n, err)
		}
	}
}

func TestCopyWipesSource(t *testing.T) {
	src := []byte("kök parolası")
	want := append([]byte(nil), src...)
	b, err := Copy(src)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("buffer = %q", b.Bytes())
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatalf("source not wiped: %q", src)
	}
	if !b.Equal(want) || b.Equal([]byte("başka")) {
		t.Fatal("Equal wrong")
	}
	if b.Len() != len(want) {
		t.Fatalf("Len = %d", b.Len())
	}
	if err := b.Use(func(s []byte) error {
		if !bytes.Equal(s, want) {
			return errors.New("Use saw other bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCopyEmptyFails(t *testing.T) {
	if _, err := Copy(nil); !errors.Is(err, ErrSize) {
		t.Fatalf("Copy(nil) = %v", err)
	}
}

func TestDestroyIsFinalAndIdempotent(t *testing.T) {
	b, err := New(32)
	if err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	for i := range data {
		data[i] = 0xAA
	}
	b.Destroy()
	b.Destroy()
	if b.Bytes() != nil || b.Len() != 0 || b.Locked() || b.Equal(nil) {
		t.Fatal("destroyed buffer still usable")
	}
	if err := b.Use(func([]byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("Use after Destroy = %v", err)
	}
	if !platformSupported {
		// Heap fallback: the old slice is still readable and must be zero.
		for _, c := range data {
			if c != 0 {
				t.Fatal("not wiped")
			}
		}
	}
	var nilBuf *Buffer
	nilBuf.Destroy()
}

func TestWipeBeforeRelease(t *testing.T) {
	// Destroy wipes the whole region, including the page tail beyond Len.
	b, err := New(10)
	if err != nil {
		t.Fatal(err)
	}
	full := b.mem.bytes()
	for i := range full {
		full[i] = 0x55
	}
	Wipe(full)
	for _, c := range full {
		if c != 0 {
			t.Fatal("region not wiped")
		}
	}
	b.Destroy()
}

func TestCapacityBoundsAppend(t *testing.T) {
	b, err := New(100)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	if cap(b.Bytes()) != 100 {
		t.Fatalf("cap = %d; an append must not write into the page tail", cap(b.Bytes()))
	}
	if Supported() {
		// A small RLIMIT_MEMLOCK may refuse the lock; that is allowed.
		t.Logf("locked: %v", b.Locked())
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	Wipe(nil)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal(b)
	}
}
