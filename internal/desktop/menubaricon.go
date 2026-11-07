package desktop

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
)

// menubar-template.png is logos/ic_launcher_monochrome-1024.png cropped
// to the mark and reduced to 44x44 (22 pt at 2x): black on transparent, a
// macOS template image that the system tints for light and dark menu
// bars. The state shows as brightness and a small badge, since a template
// image carries no colour (ADR-0227):
//
//	connected   full mark
//	exit node   full mark, filled dot
//	off         faded mark
//	warning     full mark, ring
//	error       faded mark, ring
//
//go:embed assets/menubar-template.png
var menuBarTemplatePNG []byte

const (
	menuBarFaded = 0.4
	badgeCut     = 0.24 // radius of the transparent gap around the badge
	badgeOuter   = 0.17
	badgeInner   = 0.09 // hole of the ring badge
)

type badgeKind int

const (
	badgeNone badgeKind = iota
	badgeDot
	badgeRing
)

// menuBarIcons renders the template image of every state; nil when the
// embedded image cannot be decoded (the app then shows a text title).
func menuBarIcons(src []byte) map[trayIconState][]byte {
	img, err := png.Decode(bytes.NewReader(src))
	if err != nil {
		return nil
	}
	base := image.NewNRGBA(img.Bounds())
	draw.Draw(base, base.Bounds(), img, img.Bounds().Min, draw.Src)
	out := map[trayIconState][]byte{}
	for state, look := range map[trayIconState]struct {
		alpha float64
		badge badgeKind
	}{
		iconConnected: {1, badgeNone},
		iconExit:      {1, badgeDot},
		iconOff:       {menuBarFaded, badgeNone},
		iconWarning:   {1, badgeRing},
		iconError:     {menuBarFaded, badgeRing},
	} {
		data, err := encodeMenuBarIcon(base, look.alpha, look.badge)
		if err != nil {
			return nil
		}
		out[state] = data
	}
	return out
}

func encodeMenuBarIcon(base *image.NRGBA, alpha float64, badge badgeKind) ([]byte, error) {
	b := base.Bounds()
	dst := image.NewNRGBA(b)
	w, h := float64(b.Dx()), float64(b.Dy())
	size := math.Min(w, h)
	cx, cy := w-size*badgeOuter-0.5, h-size*badgeOuter-0.5
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			a := float64(base.NRGBAAt(x, y).A) * alpha
			if badge != badgeNone {
				d := math.Hypot(float64(x-b.Min.X)-cx, float64(y-b.Min.Y)-cy) / size
				switch {
				case d <= badgeOuter && (badge == badgeDot || d >= badgeInner):
					a = 255
				case d <= badgeCut:
					a = 0
				}
			}
			dst.SetNRGBA(x, y, color.NRGBA{A: uint8(math.Round(a))})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
