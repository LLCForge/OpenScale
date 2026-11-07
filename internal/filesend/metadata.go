package filesend

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Metadata removal before sending (#139, ADR-0104). Photos carry the
// place they were taken (EXIF GPS), and XMP, IPTC and appended
// secondary images (multi-picture, depth maps) can carry it again. The
// sender can remove them before the bytes leave the device; the receiver
// gets a normal, still valid image.
//
// JPEG and PNG are rewritten in pure Go without decoding the pixels, so
// the image is bit for bit the same. Other image formats that can hold
// location (HEIC, TIFF, WebP, AVIF, camera raw) are refused rather than
// sent with their metadata: removal was asked for and cannot be done.
// Files that are not images are sent unchanged.

// MetadataMode selects what is removed.
type MetadataMode int

// Metadata modes.
const (
	// MetadataKeep sends the file unchanged.
	MetadataKeep MetadataMode = iota
	// MetadataLocation removes location: the EXIF GPS directory, XMP and
	// IPTC blocks, PNG text chunks and data after the image end. Camera,
	// orientation and color data stay.
	MetadataLocation
	// MetadataAll also removes the whole EXIF block (camera, time,
	// orientation, thumbnail), comments and PNG time chunks.
	MetadataAll
)

// ErrMetadataUnsupported is returned for image formats whose metadata
// cannot be removed.
var ErrMetadataUnsupported = errors.New("bu görüntü biçiminden üst veri temizlenemiyor; dosya gönderilmedi")

// maxStripBytes bounds the images rewritten in memory.
const maxStripBytes = 256 << 20

var unsupportedImageExts = map[string]bool{
	".heic": true, ".heif": true, ".tif": true, ".tiff": true, ".webp": true, ".avif": true,
	".dng": true, ".cr2": true, ".cr3": true, ".nef": true, ".arw": true, ".orf": true,
	".rw2": true, ".raf": true, ".gif": true, ".jxl": true,
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// StripMetadata returns data without the metadata selected by mode.
// name is only used to recognise image formats it cannot rewrite.
func StripMetadata(name string, data []byte, mode MetadataMode) ([]byte, error) {
	if mode == MetadataKeep {
		return data, nil
	}
	switch {
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return stripJPEG(data, mode)
	case bytes.HasPrefix(data, pngSignature):
		return stripPNG(data, mode)
	case unsupportedImageExts[strings.ToLower(filepath.Ext(name))]:
		return nil, ErrMetadataUnsupported
	}
	return data, nil
}

var errBadImage = errors.New("görüntü dosyası bozuk; üst veri temizlenemedi")

const (
	exifHeader = "Exif\x00\x00"
	xmpHeader  = "http://ns.adobe.com/xap/1.0/\x00"
	xmpExt     = "http://ns.adobe.com/xmp/extension/\x00"
)

// stripJPEG walks the marker segments up to the end of the image. Data
// after EOI (appended secondary images) is dropped.
func stripJPEG(data []byte, mode MetadataMode) ([]byte, error) {
	out := make([]byte, 0, len(data))
	out = append(out, 0xff, 0xd8)
	i := 2
	for {
		// Skip fill bytes before a marker.
		if i >= len(data) || data[i] != 0xff {
			return nil, errBadImage
		}
		for i < len(data) && data[i] == 0xff {
			i++
		}
		if i >= len(data) {
			return nil, errBadImage
		}
		marker := data[i]
		i++
		switch {
		case marker == 0xd9: // EOI
			return append(out, 0xff, 0xd9), nil
		case marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7):
			out = append(out, 0xff, marker)
			continue
		case marker == 0x00 || marker == 0xd8:
			return nil, errBadImage
		}
		if i+2 > len(data) {
			return nil, errBadImage
		}
		n := int(binary.BigEndian.Uint16(data[i:]))
		if n < 2 || i+n > len(data) {
			return nil, errBadImage
		}
		seg := data[i+2 : i+n]
		keep := true
		var payload []byte
		switch {
		case marker == 0xe1 && bytes.HasPrefix(seg, []byte(exifHeader)):
			if mode == MetadataAll {
				keep = false
			} else {
				payload = append([]byte(nil), seg...)
				if err := scrubGPS(payload[len(exifHeader):]); err != nil {
					// An EXIF block we cannot parse may hide a location.
					keep = false
					payload = nil
				}
			}
		case marker == 0xe1 && (bytes.HasPrefix(seg, []byte(xmpHeader)) || bytes.HasPrefix(seg, []byte(xmpExt))):
			keep = false
		case marker == 0xed: // APP13: Photoshop IRB / IPTC
			keep = false
		case marker == 0xe2 && bytes.HasPrefix(seg, []byte("MPF\x00")):
			// Multi-picture index; the pictures after EOI are dropped.
			keep = false
		case marker == 0xfe && mode == MetadataAll: // comment
			keep = false
		}
		if keep {
			out = append(out, 0xff, marker)
			out = append(out, data[i:i+2]...)
			if payload != nil {
				out = append(out, payload...)
			} else {
				out = append(out, seg...)
			}
		}
		i += n
		if marker != 0xda { // not SOS
			continue
		}
		// Entropy-coded data runs to the next marker that is not a stuffed
		// zero, a restart marker or a fill byte.
		start := i
		for {
			if i+1 >= len(data) {
				return nil, errBadImage
			}
			if data[i] == 0xff {
				b := data[i+1]
				if b != 0x00 && b != 0xff && (b < 0xd0 || b > 0xd7) {
					break
				}
			}
			i++
		}
		out = append(out, data[start:i]...)
	}
}

// scrubGPS clears the GPS directory of a TIFF/EXIF block in place: its
// entries, their values and the pointer's target are zeroed so no
// coordinate, altitude or time stamp remains, and the block keeps its
// length and every other offset.
func scrubGPS(tiff []byte) error {
	if len(tiff) < 8 {
		return errBadImage
	}
	var bo binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return errBadImage
	}
	if bo.Uint16(tiff[2:]) != 42 {
		return errBadImage
	}
	size := int64(len(tiff))
	ifd0 := int64(bo.Uint32(tiff[4:]))
	if ifd0+2 > size {
		return errBadImage
	}
	n := int64(bo.Uint16(tiff[ifd0:]))
	if ifd0+2+n*12 > size {
		return errBadImage
	}
	for k := range n {
		e := ifd0 + 2 + k*12
		if bo.Uint16(tiff[e:]) != 0x8825 {
			continue
		}
		gps := int64(bo.Uint32(tiff[e+8:]))
		if gps == 0 {
			return nil
		}
		if gps+2 > size {
			return errBadImage
		}
		m := int64(bo.Uint16(tiff[gps:]))
		end := gps + 2 + m*12
		if end > size {
			return errBadImage
		}
		for j := range m {
			g := gps + 2 + j*12
			typ, count := bo.Uint16(tiff[g+2:]), int64(bo.Uint32(tiff[g+4:]))
			unit := tiffTypeSize(typ)
			if unit == 0 || count > size {
				continue
			}
			if l := unit * count; l > 4 {
				off := int64(bo.Uint32(tiff[g+8:]))
				if off >= 0 && off+l <= size {
					clear(tiff[off : off+l])
				}
			}
		}
		// Entries, count and the next-directory pointer.
		clear(tiff[gps:min(end+4, size)])
		return nil
	}
	return nil
}

func tiffTypeSize(t uint16) int64 {
	switch t {
	case 1, 2, 6, 7: // BYTE, ASCII, SBYTE, UNDEFINED
		return 1
	case 3, 8: // SHORT, SSHORT
		return 2
	case 4, 9, 11, 13: // LONG, SLONG, FLOAT, IFD
		return 4
	case 5, 10, 12: // RATIONAL, SRATIONAL, DOUBLE
		return 8
	}
	return 0
}

// stripPNG drops text, EXIF and (in MetadataAll) time chunks and anything
// after IEND. Chunk CRCs are copied unchanged.
func stripPNG(data []byte, mode MetadataMode) ([]byte, error) {
	out := append(make([]byte, 0, len(data)), pngSignature...)
	i := len(pngSignature)
	for {
		if i+12 > len(data) {
			return nil, errBadImage
		}
		n := int64(binary.BigEndian.Uint32(data[i:]))
		end := int64(i) + 12 + n
		if n > int64(len(data)) || end > int64(len(data)) {
			return nil, errBadImage
		}
		typ := string(data[i+4 : i+8])
		drop := false
		switch typ {
		case "eXIf", "tEXt", "iTXt", "zTXt":
			drop = true
		case "tIME":
			drop = mode == MetadataAll
		}
		if !drop {
			out = append(out, data[i:end]...)
		}
		i = int(end)
		if typ == "IEND" {
			return out, nil
		}
	}
}

// SendWithoutMetadata removes metadata as selected by mode and sends the
// result. The original file is never modified; a stripped copy is written
// owner-only to the temporary directory and removed afterwards.
func SendWithoutMetadata(ctx context.Context, addr netip.AddrPort, path string, mode MetadataMode, opts *SendOptions) (SendResult, error) {
	if mode == MetadataKeep {
		return Send(ctx, addr, path, opts)
	}
	f, err := os.Open(path)
	if err != nil {
		return SendResult{}, fmt.Errorf("dosya açılamadı: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStripBytes+1))
	_ = f.Close()
	if err != nil {
		return SendResult{}, fmt.Errorf("dosya okunamadı: %w", err)
	}
	if len(data) > maxStripBytes {
		if isStrippableImage(path, data) {
			return SendResult{}, errors.New("görüntü üst veri temizlemek için çok büyük (en çok 256 MiB)")
		}
		return Send(ctx, addr, path, opts)
	}
	clean, err := StripMetadata(path, data, mode)
	if err != nil {
		return SendResult{}, err
	}
	if bytes.Equal(clean, data) {
		return Send(ctx, addr, path, opts)
	}
	o := SendOptions{}
	if opts != nil {
		o = *opts
	}
	if o.Name == "" {
		o.Name = filepath.Base(path)
	}
	dir := o.TempDir
	if dir == "" {
		dir = filepath.Dir(path)
	}
	tmp, err := os.CreateTemp(dir, ".openscale-send-*")
	if err != nil {
		return SendResult{}, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(clean); err != nil {
		_ = tmp.Close()
		return SendResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return SendResult{}, err
	}
	return Send(ctx, addr, tmp.Name(), &o)
}

func isStrippableImage(name string, data []byte) bool {
	return (len(data) >= 2 && data[0] == 0xff && data[1] == 0xd8) || bytes.HasPrefix(data, pngSignature) ||
		unsupportedImageExts[strings.ToLower(filepath.Ext(name))]
}
