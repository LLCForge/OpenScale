package filesend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 32, 24))
	for y := range 24 {
		for x := range 32 {
			img.Set(x, y, color.RGBA{uint8(x * 8), uint8(y * 10), 90, 255})
		}
	}
	return img
}

var secretCoord = bytes.Repeat([]byte("KOORDINAT"), 3)[:24]

// exifWithGPS builds an EXIF block whose GPS directory holds a latitude.
func exifWithGPS(bo binary.AppendByteOrder, mark string) []byte {
	t := bo.AppendUint16([]byte(mark), 42)
	t = bo.AppendUint32(t, 8)
	// IFD0 at 8: one entry, GPS pointer to 26.
	t = bo.AppendUint16(t, 1)
	t = bo.AppendUint16(t, 0x8825)
	t = bo.AppendUint16(t, 4)
	t = bo.AppendUint32(t, 1)
	t = bo.AppendUint32(t, 26)
	t = bo.AppendUint32(t, 0)
	// GPS IFD at 26: latitude, 3 rationals at 44.
	t = bo.AppendUint16(t, 1)
	t = bo.AppendUint16(t, 0x0002)
	t = bo.AppendUint16(t, 5)
	t = bo.AppendUint32(t, 3)
	t = bo.AppendUint32(t, 44)
	t = bo.AppendUint32(t, 0)
	return append(t, secretCoord...)
}

func jpegSegment(marker byte, payload []byte) []byte {
	s := []byte{0xff, marker, 0, 0}
	binary.BigEndian.PutUint16(s[2:], uint16(len(payload)+2))
	return append(s, payload...)
}

func photoJPEG(t *testing.T, bo binary.AppendByteOrder, mark string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, testImage(), &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	enc := buf.Bytes()
	var out []byte
	out = append(out, enc[:2]...)
	out = append(out, jpegSegment(0xe1, append([]byte(exifHeader), exifWithGPS(bo, mark)...))...)
	out = append(out, jpegSegment(0xe1, []byte(xmpHeader+"<exif:GPSLatitude>41,0N</exif:GPSLatitude>"))...)
	out = append(out, jpegSegment(0xed, []byte("Photoshop 3.0\x00IPTC-CITY"))...)
	out = append(out, jpegSegment(0xfe, []byte("yorum"))...)
	out = append(out, enc[2:]...)
	return append(out, []byte("MPF-SECOND-IMAGE-GPS")...)
}

func TestStripJPEG(t *testing.T) {
	for _, tc := range []struct {
		bo   binary.AppendByteOrder
		mark string
	}{{binary.LittleEndian, "II"}, {binary.BigEndian, "MM"}} {
		data := photoJPEG(t, tc.bo, tc.mark)
		want, err := jpeg.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []MetadataMode{MetadataLocation, MetadataAll} {
			out, err := StripMetadata("foto.jpg", data, mode)
			if err != nil {
				t.Fatal(err)
			}
			for _, leak := range [][]byte{secretCoord, []byte("GPSLatitude"), []byte("IPTC-CITY"), []byte("SECOND-IMAGE")} {
				if bytes.Contains(out, leak) {
					t.Fatalf("mode %d leaks %q", mode, leak)
				}
			}
			if hasExif := bytes.Contains(out, []byte(exifHeader)); hasExif != (mode == MetadataLocation) {
				t.Fatalf("mode %d: EXIF kept=%v", mode, hasExif)
			}
			if hasComment := bytes.Contains(out, []byte("yorum")); hasComment != (mode == MetadataLocation) {
				t.Fatalf("mode %d: comment kept=%v", mode, hasComment)
			}
			got, err := jpeg.Decode(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("stripped JPEG does not decode: %v", err)
			}
			if !bytes.Equal(got.(*image.YCbCr).Y, want.(*image.YCbCr).Y) {
				t.Fatal("pixels changed")
			}
		}
	}
	if out, err := StripMetadata("x.jpg", photoJPEG(t, binary.BigEndian, "MM"), MetadataKeep); err != nil || !bytes.Contains(out, secretCoord) {
		t.Fatal("MetadataKeep must not change the file")
	}
}

func pngChunk(typ string, data []byte) []byte {
	c := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	c = append(c, typ...)
	c = append(c, data...)
	return binary.BigEndian.AppendUint32(c, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

func TestStripPNG(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage()); err != nil {
		t.Fatal(err)
	}
	enc := buf.Bytes()
	iend := bytes.LastIndex(enc, []byte("IEND")) - 4
	var data []byte
	data = append(data, enc[:iend]...)
	data = append(data, pngChunk("tEXt", []byte("Location\x00Ankara"))...)
	data = append(data, pngChunk("eXIf", exifWithGPS(binary.BigEndian, "MM"))...)
	data = append(data, enc[iend:]...)
	data = append(data, []byte("trailing")...)
	out, err := StripMetadata("a.png", data, MetadataLocation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Ankara")) || bytes.Contains(out, secretCoord) || bytes.Contains(out, []byte("trailing")) {
		t.Fatal("PNG metadata kept")
	}
	got, err := png.Decode(bytes.NewReader(out))
	if err != nil || !bytes.Equal(got.(*image.RGBA).Pix, testImage().Pix) {
		t.Fatalf("stripped PNG: %v", err)
	}
}

func TestStripUnsupportedAndPlain(t *testing.T) {
	if _, err := StripMetadata("IMG_1.HEIC", []byte("....ftypheic"), MetadataLocation); !errors.Is(err, ErrMetadataUnsupported) {
		t.Fatalf("HEIC: %v", err)
	}
	if out, err := StripMetadata("notlar.txt", []byte("merhaba"), MetadataAll); err != nil || string(out) != "merhaba" {
		t.Fatal("plain files are sent unchanged")
	}
	if _, err := StripMetadata("x.jpg", []byte{0xff, 0xd8, 0xff, 0xe1, 0xff}, MetadataLocation); err == nil {
		t.Fatal("broken JPEG accepted")
	}
}

func TestSendWithoutMetadata(t *testing.T) {
	h := newHarness(t, Config{})
	p := writeTemp(t, "foto.jpg", photoJPEG(t, binary.LittleEndian, "II"))
	res, err := SendWithoutMetadata(ctx(t), h.addr, p, MetadataLocation, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(h.inbox, res.SavedName))
	if err != nil || res.SavedName != "foto.jpg" || bytes.Contains(got, secretCoord) {
		t.Fatalf("received %q: %v", res.SavedName, err)
	}
	if orig, _ := os.ReadFile(p); !bytes.Contains(orig, secretCoord) {
		t.Fatal("original file modified")
	}
}

func TestOutbox(t *testing.T) {
	var mu sync.Mutex
	accept := true
	h := newHarness(t, Config{Accept: func(netip.Addr, string, int64) bool { mu.Lock(); defer mu.Unlock(); return accept }})
	online := false
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var done []error
	cfg := OutboxConfig{
		File: filepath.Join(t.TempDir(), "state", "outbox.json"),
		Resolve: func(peer string) (netip.AddrPort, bool) {
			if peer != "telefon" {
				t.Errorf("peer %q", peer)
			}
			return h.addr, online
		},
		OnDone: func(_ OutboxItem, _ SendResult, err error) { done = append(done, err) },
		Now:    func() time.Time { return now },
	}
	o, err := OpenOutbox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := writeTemp(t, "a.txt", []byte("bekleyen dosya"))
	b := writeTemp(t, "b.txt", []byte("degisecek"))
	c := writeTemp(t, "c.txt", []byte("reddedilecek"))
	for _, p := range []string{a, b} {
		if _, err := o.Enqueue("telefon", p, "", MetadataKeep); err != nil {
			t.Fatal(err)
		}
	}
	if n := o.RunOnce(ctx(t)); n != 0 || len(o.Items()) != 2 {
		t.Fatal("sent while the recipient is offline")
	}
	// The queue survives a restart.
	o, err = OpenOutbox(cfg)
	if err != nil || len(o.Items()) != 2 {
		t.Fatalf("reopen: %v", err)
	}
	if err := os.WriteFile(b, []byte("değişti"), 0o600); err != nil {
		t.Fatal(err)
	}
	online = true
	if n := o.RunOnce(ctx(t)); n != 1 {
		t.Fatalf("sent %d", n)
	}
	if got, err := os.ReadFile(filepath.Join(h.inbox, "a.txt")); err != nil || string(got) != "bekleyen dosya" {
		t.Fatalf("inbox: %q %v", got, err)
	}
	if len(done) != 2 || done[0] != nil || !errors.Is(done[1], ErrFileChanged) || len(o.Items()) != 0 {
		t.Fatalf("results %v, left %d", done, len(o.Items()))
	}
	// A refusal is final; an expired item is dropped.
	mu.Lock()
	accept = false
	mu.Unlock()
	if _, err := o.Enqueue("telefon", c, "", MetadataKeep); err != nil {
		t.Fatal(err)
	}
	o.RunOnce(ctx(t))
	if !errors.Is(done[len(done)-1], ErrRejected) || len(o.Items()) != 0 {
		t.Fatalf("refusal: %v", done)
	}
	online = false
	if _, err := o.Enqueue("telefon", c, "", MetadataKeep); err != nil {
		t.Fatal(err)
	}
	now = now.Add(8 * 24 * time.Hour)
	o.RunOnce(ctx(t))
	if !errors.Is(done[len(done)-1], ErrExpired) || len(o.Items()) != 0 {
		t.Fatalf("expiry: %v", done)
	}
}

func FuzzStripMetadata(f *testing.F) {
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, testImage(), nil)
	f.Add(buf.Bytes())
	buf.Reset()
	_ = png.Encode(&buf, testImage())
	f.Add(buf.Bytes())
	f.Add(append([]byte{0xff, 0xd8, 0xff, 0xe1, 0, 40}, append([]byte(exifHeader), exifWithGPS(binary.BigEndian, "MM")...)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, mode := range []MetadataMode{MetadataLocation, MetadataAll} {
			out, err := StripMetadata("f.jpg", data, mode)
			if err == nil && len(out) > len(data)+4 {
				t.Fatalf("output grew: %d > %d", len(out), len(data))
			}
		}
	})
}
