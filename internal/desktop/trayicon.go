package desktop

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"

	"github.com/openscale/openscale/internal/panel"
)

// trayIconState is what the tray icon shows (F-155).
type trayIconState int

const (
	// iconOff: the tunnel is off, connecting or not set up.
	iconOff trayIconState = iota
	// iconConnected: the tunnel runs and is in sync.
	iconConnected
	// iconExit: connected and internet traffic leaves through an exit node.
	iconExit
	// iconWarning: connected, but something needs attention.
	iconWarning
	// iconError: the service is unreachable or the tunnel is down.
	iconError
)

// Badge colors; each keeps at least 3:1 contrast against the dark ring
// around it, so it reads on light and dark taskbars alike.
var trayBadgeColors = map[trayIconState]color.RGBA{
	iconOff:       {R: 0x9c, G: 0xa3, B: 0xaf, A: 0xff},
	iconConnected: {R: 0x22, G: 0xc5, B: 0x5e, A: 0xff},
	iconExit:      {R: 0x38, G: 0xbd, B: 0xf8, A: 0xff},
	iconWarning:   {R: 0xf5, G: 0x9e, B: 0x0b, A: 0xff},
	iconError:     {R: 0xef, G: 0x44, B: 0x44, A: 0xff},
}

// trayStateLabel is the state name for the tooltip and tests.
var trayStateLabel = map[trayIconState]string{
	iconOff: "kapalı", iconConnected: "bağlı", iconExit: "çıkış düğümü", iconWarning: "uyarı", iconError: "hata",
}

// iconStateFor maps the service status to an icon state.
func iconStateFor(st panel.AppStatus, reachable bool) trayIconState {
	if !reachable {
		return iconError
	}
	dev := st.Device
	if dev == nil || dev.Name == "" || !dev.Connected {
		for _, a := range st.Health {
			if a.Level == panel.LevelDanger {
				return iconError
			}
		}
		return iconOff
	}
	if !dev.Running {
		if dev.Error != "" {
			return iconError
		}
		return iconOff
	}
	worst := ""
	for _, a := range st.Health {
		switch a.Level {
		case panel.LevelDanger:
			worst = panel.LevelDanger
		case panel.LevelWarning:
			if worst == "" {
				worst = panel.LevelWarning
			}
		}
	}
	switch {
	case worst == panel.LevelDanger:
		return iconError
	case worst == panel.LevelWarning:
		return iconWarning
	case dev.LastSync == nil:
		return iconOff
	case dev.ExitNode != "":
		return iconExit
	}
	return iconConnected
}

// makeTrayIcons renders a badge variant of base for every state. A state
// whose variant fails gets base itself, so the tray always has an icon.
func makeTrayIcons(base []byte) map[trayIconState][]byte {
	out := make(map[trayIconState][]byte, len(trayBadgeColors))
	for s, c := range trayBadgeColors {
		img, err := badgeIcon(base, c)
		if err != nil {
			img = base
		}
		out[s] = img
	}
	return out
}

// badgeIcon draws a colored dot with a dark ring in the bottom-right
// corner of the PNG base. The dot covers about 40% of the width so it is
// still visible when Windows scales the icon down to 16 pixels.
func badgeIcon(base []byte, c color.RGBA) ([]byte, error) {
	src, err := png.Decode(bytes.NewReader(base))
	if err != nil {
		return nil, err
	}
	b := src.Bounds()
	img := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(img, img.Bounds(), src, b.Min, draw.Src)

	size := float64(min(b.Dx(), b.Dy()))
	outer := size * 0.22 // ring radius
	inner := outer - math.Max(1.5, size*0.045)
	cx, cy := float64(b.Dx())-outer-0.5, float64(b.Dy())-outer-0.5
	ring := color.RGBA{R: 0x11, G: 0x18, B: 0x27, A: 0xff}
	for y := int(cy - outer - 1); y <= int(cy+outer+1); y++ {
		for x := int(cx - outer - 1); x <= int(cx+outer+1); x++ {
			if !(image.Point{X: x, Y: y}).In(img.Bounds()) {
				continue
			}
			d := math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy)
			// Anti-aliased edges: coverage falls off over one pixel.
			if a := coverage(outer - d); a > 0 {
				blend(img, x, y, ring, a)
			}
			if a := coverage(inner - d); a > 0 {
				blend(img, x, y, c, a)
			}
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func coverage(edge float64) float64 {
	return math.Max(0, math.Min(1, edge+0.5))
}

// blend paints c over the pixel with coverage a (straight alpha).
func blend(img *image.NRGBA, x, y int, c color.RGBA, a float64) {
	dst := img.NRGBAAt(x, y)
	da := float64(dst.A) / 255
	oa := a + da*(1-a)
	if oa == 0 {
		return
	}
	mix := func(s, d uint8) uint8 {
		return uint8(math.Round((float64(s)*a + float64(d)*da*(1-a)) / oa))
	}
	img.SetNRGBA(x, y, color.NRGBA{R: mix(c.R, dst.R), G: mix(c.G, dst.G), B: mix(c.B, dst.B), A: uint8(math.Round(oa * 255))})
}
