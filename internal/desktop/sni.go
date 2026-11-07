package desktop

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"slices"
	"strings"
	"sync"

	"github.com/openscale/openscale/internal/dbuswire"
	"github.com/openscale/openscale/internal/winapp"
)

// The Linux tray's D-Bus model (ADR-0234), kept free of the bus so it is
// tested on every system: the shared menu (menubar_menu.go) as a
// com.canonical.dbusmenu layout, and the StatusNotifierItem icon as
// ARGB32 pixmaps. tray_linux.go exports both on the session bus.

// dbusmenu layout constants.
const (
	// dbusMenuRoot is the id of the invisible root item.
	dbusMenuRoot int32 = 0
	// dbusMenuSynthetic is where ids of items without an action begin
	// (labels, separators, submenus); action items keep their menu id.
	dbusMenuSynthetic int32 = 1_000_000
	// dbusMenuVersion is the protocol version the menu speaks.
	dbusMenuVersion uint32 = 3
	// layoutSig is one dbusmenu item: id, properties, children.
	layoutSig = "(ia{sv}av)"
)

// menuNode is one dbusmenu item.
type menuNode struct {
	id       int32
	props    map[string]dbuswire.Variant
	children []*menuNode
}

// dbusMenu is the exported menu: the current layout and its revision.
type dbusMenu struct {
	mu       sync.Mutex
	revision uint32
	root     *menuNode
	nodes    map[int32]*menuNode
	// actions maps an item id to the shared menu's id it runs.
	actions map[int32]int
	// shape is the layout's text form, to tell whether it changed.
	shape string
}

func newDBusMenu() *dbusMenu {
	root := &menuNode{id: dbusMenuRoot, props: map[string]dbuswire.Variant{"children-display": dbuswire.MakeVariant("submenu")}}
	return &dbusMenu{revision: 1, root: root, nodes: map[int32]*menuNode{dbusMenuRoot: root}, actions: map[int32]int{}}
}

// checkableItem reports whether a menu id is a check item (it shows an
// empty box while unchecked).
func checkableItem(id int) bool {
	switch {
	case id == mbAutostart, id == mbKillSwitch, id == mbExitNone, id >= mbExitBase:
		return true
	}
	return false
}

// menuLabel is the dbusmenu label: "_" starts a mnemonic there, so it is
// doubled; the detail follows the label.
func menuLabel(it winapp.MenuItem) string {
	l := it.Label
	if it.Detail != "" {
		l += " · " + it.Detail
	}
	return strings.ReplaceAll(l, "_", "__")
}

// set replaces the layout and reports whether it changed (the revision
// then moved on and LayoutUpdated must be sent).
func (m *dbusMenu) set(items []winapp.MenuItem) (uint32, bool) {
	nodes := map[int32]*menuNode{}
	actions := map[int32]int{}
	next := dbusMenuSynthetic
	var shape strings.Builder
	var build func(items []winapp.MenuItem, depth int) []*menuNode
	build = func(items []winapp.MenuItem, depth int) []*menuNode {
		var out []*menuNode
		for _, it := range items {
			n := &menuNode{props: map[string]dbuswire.Variant{}}
			if it.ID > 0 && len(it.Children) == 0 && !it.Separator {
				n.id = int32(it.ID)
				actions[n.id] = it.ID
			} else {
				n.id = next
				next++
			}
			if _, dup := nodes[n.id]; dup {
				// A repeated id (never in the shared menu) gets its own.
				delete(actions, n.id)
				n.id = next
				next++
			}
			switch {
			case it.Separator:
				n.props["type"] = dbuswire.MakeVariant("separator")
			default:
				n.props["label"] = dbuswire.MakeVariant(menuLabel(it))
				if it.Disabled {
					n.props["enabled"] = dbuswire.MakeVariant(false)
				}
				if checkableItem(it.ID) || it.Checked {
					n.props["toggle-type"] = dbuswire.MakeVariant("checkmark")
					state := int32(0)
					if it.Checked {
						state = 1
					}
					n.props["toggle-state"] = dbuswire.MakeVariant(state)
				}
				if len(it.Children) > 0 {
					n.props["children-display"] = dbuswire.MakeVariant("submenu")
				}
			}
			fmt.Fprintf(&shape, "%d|%d|%q|%v|%v|%v|%v\n", depth, n.id, it.Label+"\x00"+it.Detail, it.Disabled, it.Checked, it.Separator, len(it.Children))
			nodes[n.id] = n
			if len(it.Children) > 0 {
				n.children = build(it.Children, depth+1)
			}
			out = append(out, n)
		}
		return out
	}
	children := build(items, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if shape.String() == m.shape {
		return m.revision, false
	}
	root := &menuNode{id: dbusMenuRoot, props: map[string]dbuswire.Variant{"children-display": dbuswire.MakeVariant("submenu")}, children: children}
	nodes[dbusMenuRoot] = root
	m.root, m.nodes, m.actions, m.shape = root, nodes, actions, shape.String()
	m.revision++
	return m.revision, true
}

// action returns the shared menu id of an item.
func (m *dbusMenu) action(id int32) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.actions[id]
	return a, ok
}

// Limits of what a menu host may ask for.
const (
	maxMenuProps = 32
	maxMenuIDs   = 256
)

func filterProps(props map[string]dbuswire.Variant, names []string) map[string]dbuswire.Variant {
	if len(names) == 0 {
		return props
	}
	out := map[string]dbuswire.Variant{}
	for _, n := range names {
		if v, ok := props[n]; ok {
			out[n] = v
		}
	}
	return out
}

func encodeNode(n *menuNode, depth int32, names []string) dbuswire.Struct {
	children := []any{}
	if depth != 0 {
		next := depth - 1
		if depth < 0 {
			next = -1
		}
		for _, c := range n.children {
			children = append(children, dbuswire.NewVariant(layoutSig, encodeNode(c, next, names)))
		}
	}
	return dbuswire.Struct{n.id, filterProps(n.props, names), children}
}

// errMenuItem: the host asked for an item that is not in the layout.
var errMenuItem = errors.New("dbusmenu: no such item")

// layout answers GetLayout(parentId, recursionDepth, propertyNames).
func (m *dbusMenu) layout(parent, depth int32, names []string) (uint32, dbuswire.Struct, error) {
	if len(names) > maxMenuProps {
		names = names[:maxMenuProps]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[parent]
	if !ok {
		return 0, nil, errMenuItem
	}
	return m.revision, encodeNode(n, depth, names), nil
}

// groupProperties answers GetGroupProperties(ids, propertyNames): every
// item when ids is empty, unknown ids left out.
func (m *dbusMenu) groupProperties(ids []int32, names []string) []any {
	if len(names) > maxMenuProps {
		names = names[:maxMenuProps]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(ids) == 0 {
		for id := range m.nodes {
			ids = append(ids, id)
		}
		slices.Sort(ids)
	}
	if len(ids) > maxMenuIDs {
		ids = ids[:maxMenuIDs]
	}
	out := []any{}
	for _, id := range ids {
		if n, ok := m.nodes[id]; ok {
			out = append(out, dbuswire.Struct{id, filterProps(n.props, names)})
		}
	}
	return out
}

// property answers GetProperty(id, name).
func (m *dbusMenu) property(id int32, name string) (dbuswire.Variant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return dbuswire.Variant{}, errMenuItem
	}
	v, ok := n.props[name]
	if !ok {
		return dbuswire.Variant{}, errMenuItem
	}
	return v, nil
}

// knows reports whether id is an item of the layout.
func (m *dbusMenu) knows(id int32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.nodes[id]
	return ok
}

// sniIconSizes are the pixmap sizes sent with the icon; hosts pick the
// closest one (panels are 16 to 48 pixels high, HiDPI doubles that).
var sniIconSizes = []int{16, 22, 24, 32, 48, 64}

// maxIconSource bounds the decoded source icon.
const maxIconSource = 512

// sniPixmaps turns a PNG into StatusNotifierItem pixmaps: (width, height,
// ARGB32 bytes in network byte order, not premultiplied) for each size.
func sniPixmaps(data []byte, sizes []int) ([]dbuswire.Struct, error) {
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxIconSource || cfg.Height > maxIconSource {
		return nil, errors.New("simge boyutu desteklenmiyor")
	}
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	b := src.Bounds()
	rgba := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(rgba, rgba.Bounds(), src, b.Min, draw.Src)
	out := make([]dbuswire.Struct, 0, len(sizes))
	for _, s := range sizes {
		if s <= 0 || s > maxIconSource {
			continue
		}
		out = append(out, dbuswire.Struct{int32(s), int32(s), scaleARGB(rgba, s)})
	}
	return out, nil
}

// scaleARGB scales img to size x size with an area average over
// premultiplied colour and returns ARGB32 bytes (A, R, G, B per pixel).
func scaleARGB(img *image.NRGBA, size int) []byte {
	sw, sh := img.Rect.Dx(), img.Rect.Dy()
	out := make([]byte, 0, size*size*4)
	for y := 0; y < size; y++ {
		y0, y1 := y*sh/size, max((y+1)*sh/size, y*sh/size+1)
		for x := 0; x < size; x++ {
			x0, x1 := x*sw/size, max((x+1)*sw/size, x*sw/size+1)
			var a, r, g, bl, n uint64
			for sy := y0; sy < y1 && sy < sh; sy++ {
				for sx := x0; sx < x1 && sx < sw; sx++ {
					p := img.NRGBAAt(sx, sy)
					pa := uint64(p.A)
					a += pa
					r += uint64(p.R) * pa
					g += uint64(p.G) * pa
					bl += uint64(p.B) * pa
					n++
				}
			}
			if n == 0 || a == 0 {
				out = append(out, 0, 0, 0, 0)
				continue
			}
			out = append(out, byte(a/n), byte(r/a), byte(g/a), byte(bl/a))
		}
	}
	return out
}

// sniStatus is the StatusNotifierItem Status of an icon state.
func sniStatus(s trayIconState) string {
	switch s {
	case iconWarning, iconError:
		return "NeedsAttention"
	}
	return "Active"
}

// sniToolTip is the ToolTip property: (icon name, icon pixmaps, title,
// text).
func sniToolTip(title, text string) dbuswire.Struct {
	return dbuswire.Struct{"", []any{}, title, text}
}

// trayLabelText splits the tooltip "OpenScale: Bağlı (çıkış: x)" into a
// title and text for hosts that show both.
func trayLabelText(tip string) (string, string) {
	title, text, ok := strings.Cut(tip, ": ")
	if !ok {
		return "OpenScale", tip
	}
	return title, text
}
