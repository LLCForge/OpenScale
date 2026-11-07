//go:build linux

package rdesk

import (
	"context"
	"errors"
	"fmt"
	"image"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/dbuswire"
)

// The portal side of the Wayland remote desktop (ADR-0236): one portal
// session per rdesk session. A control session is a RemoteDesktop session
// with a ScreenCast source selected on it (pointer events need a stream to
// be absolute in); a view session is a ScreenCast session only, so the
// user is never asked for more than the viewer may do.

const (
	// portalCallTimeout bounds a portal call without user interaction.
	portalCallTimeout = 15 * time.Second
	// portalUserTimeout is how long the user has for the portal dialog.
	portalUserTimeout = 2 * time.Minute
	// firstFrameWait is how long a new session waits for every stream's
	// first frame (its real size).
	firstFrameWait = 5 * time.Second
)

func init() {
	platformDevices = waylandDevices
}

// waylandDevices opens the portal session in a Wayland session; X11 keeps
// the separate capturer and injector.
func waylandDevices(control bool) (Capturer, Injector, bool, error) {
	if !WaylandSession() {
		return nil, nil, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), portalUserTimeout+30*time.Second)
	defer cancel()
	s, err := openPortalSession(ctx, control)
	if err != nil {
		return nil, nil, true, err
	}
	c := &waylandCapturer{s: s}
	if !control {
		return c, nil, true, nil
	}
	s.retain()
	return c, &waylandInjector{s: s}, true, nil
}

// portalSession is one portal session with its PipeWire streams. Capturer
// and injector share it; the last Close ends it.
type portalSession struct {
	bus     *dbuswire.Conn
	owner   string
	handle  dbuswire.ObjectPath
	remote  bool
	streams []portalStream
	pw      pipewireFrames

	mu   sync.Mutex
	refs int
}

func (s *portalSession) retain() {
	s.mu.Lock()
	s.refs++
	s.mu.Unlock()
}

func (s *portalSession) release() {
	s.mu.Lock()
	s.refs--
	last := s.refs == 0
	s.mu.Unlock()
	if !last {
		return
	}
	if s.pw != nil {
		s.pw.close()
	}
	if s.handle != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = s.bus.Call(ctx, portalBus, s.handle, portalSessionIface, "Close", "")
		cancel()
	}
	_ = s.bus.Close()
}

func openPortalSession(ctx context.Context, control bool) (*portalSession, error) {
	bus, err := dbuswire.DialSession(ctx, dbuswire.Options{UnixFD: true})
	if err != nil {
		return nil, fmt.Errorf("%w: oturum D-Bus'ı: %v", ErrUnsupported, err)
	}
	s := &portalSession{bus: bus, remote: control, refs: 1}
	ok := false
	defer func() {
		if !ok {
			s.release()
		}
	}()
	if !bus.UnixFD() {
		return nil, fmt.Errorf("%w: oturum D-Bus'ı dosya tanımlayıcısı geçirmiyor", ErrUnsupported)
	}
	if err := s.checkPortal(ctx, control); err != nil {
		return nil, err
	}
	if err := s.create(ctx); err != nil {
		return nil, err
	}
	if control {
		if _, err := s.request(ctx, portalRemote, "SelectDevices", "oa{sv}", []any{s.handle}, map[string]dbuswire.Variant{
			"types": dbuswire.MakeVariant(deviceKeyboard | devicePointer),
		}); err != nil {
			return nil, err
		}
	}
	if _, err := s.request(ctx, portalScreenCast, "SelectSources", "oa{sv}", []any{s.handle}, map[string]dbuswire.Variant{
		"types":       dbuswire.MakeVariant(sourceMonitor),
		"multiple":    dbuswire.MakeVariant(true),
		"cursor_mode": dbuswire.MakeVariant(s.cursorMode(ctx)),
	}); err != nil {
		return nil, err
	}
	startIface := portalScreenCast
	if control {
		startIface = portalRemote
	}
	results, err := s.request(ctx, startIface, "Start", "osa{sv}", []any{s.handle, ""}, map[string]dbuswire.Variant{})
	if err != nil {
		return nil, err
	}
	if control {
		granted, _ := results["devices"].Value.(uint32)
		if granted&devicePointer == 0 || granted&deviceKeyboard == 0 {
			return nil, fmt.Errorf("%w: fare ve klavye izni verilmedi", ErrPortalDenied)
		}
	}
	if s.streams, err = parseStreams(results); err != nil {
		return nil, err
	}
	if err := s.openPipeWire(ctx); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *portalSession) getProperty(ctx context.Context, iface, name string) (dbuswire.Variant, error) {
	cctx, cancel := context.WithTimeout(ctx, portalCallTimeout)
	defer cancel()
	m, err := s.bus.Call(cctx, portalBus, portalPath, dbuswire.PropertiesInterface, "Get", "ss", iface, name)
	if err != nil {
		return dbuswire.Variant{}, err
	}
	v, ok := m.Body[0].(dbuswire.Variant)
	if !ok {
		return dbuswire.Variant{}, errors.New("rdesk: portal yanıtı bozuk")
	}
	return v, nil
}

// checkPortal makes sure the portal can share a monitor (and take input)
// and learns its unique name; the first call starts a portal that is
// activated on demand.
func (s *portalSession) checkPortal(ctx context.Context, control bool) error {
	v, err := s.getProperty(ctx, portalScreenCast, "AvailableSourceTypes")
	if err != nil {
		return fmt.Errorf("%w: xdg-desktop-portal ekran paylaşımı yok: %v", ErrUnsupported, err)
	}
	if types, _ := v.Value.(uint32); types&sourceMonitor == 0 {
		return fmt.Errorf("%w: portal monitör paylaşmıyor", ErrUnsupported)
	}
	if control {
		v, err := s.getProperty(ctx, portalRemote, "AvailableDeviceTypes")
		if err != nil {
			return fmt.Errorf("%w: xdg-desktop-portal uzak masaüstü arayüzü yok: %v", ErrUnsupported, err)
		}
		if types, _ := v.Value.(uint32); types&(deviceKeyboard|devicePointer) != deviceKeyboard|devicePointer {
			return fmt.Errorf("%w: portal fare ve klavye girdisi sunmuyor", ErrUnsupported)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, portalCallTimeout)
	defer cancel()
	owner, err := s.bus.NameOwner(cctx, portalBus)
	if err != nil {
		return fmt.Errorf("%w: portal bulunamadı: %v", ErrUnsupported, err)
	}
	s.owner = owner
	return nil
}

func (s *portalSession) cursorMode(ctx context.Context) uint32 {
	if v, err := s.getProperty(ctx, portalScreenCast, "AvailableCursorModes"); err == nil {
		if modes, _ := v.Value.(uint32); modes&cursorEmbedded != 0 {
			return cursorEmbedded
		}
	}
	return cursorHidden
}

// create makes the session (RemoteDesktop for control, else ScreenCast).
func (s *portalSession) create(ctx context.Context) error {
	iface := portalScreenCast
	if s.remote {
		iface = portalRemote
	}
	results, err := s.request(ctx, iface, "CreateSession", "a{sv}", nil, map[string]dbuswire.Variant{
		"session_handle_token": dbuswire.MakeVariant(newPortalToken()),
	})
	if err != nil {
		return err
	}
	switch h := results["session_handle"].Value.(type) {
	case string:
		s.handle = dbuswire.ObjectPath(h)
	case dbuswire.ObjectPath:
		s.handle = h
	}
	if !dbuswire.ValidObjectPath(string(s.handle)) {
		s.handle = ""
		return errors.New("rdesk: portal oturum tanıtıcısı vermedi")
	}
	return nil
}

// request calls a portal method that answers through a Request object
// and waits for its Response. The signal is subscribed before the call,
// on the path the portal will use for our handle token, and only the
// portal's own signal counts.
func (s *portalSession) request(ctx context.Context, iface, method string, sig dbuswire.Signature, args []any, options map[string]dbuswire.Variant) (map[string]dbuswire.Variant, error) {
	token := newPortalToken()
	options["handle_token"] = dbuswire.MakeVariant(token)
	path := portalRequestPath(s.bus.UniqueName(), token)
	sctx, cancel := context.WithTimeout(ctx, portalCallTimeout)
	sub, err := s.bus.Subscribe(sctx, dbuswire.Match{Sender: s.owner, Path: path, Interface: portalRequest, Member: "Response"}, 2)
	cancel()
	if err != nil {
		return nil, err
	}
	defer sub.Close()
	cctx, cancel := context.WithTimeout(ctx, portalCallTimeout)
	reply, err := s.bus.Do(cctx, dbuswire.Call{
		Destination: portalBus, Path: portalPath, Interface: iface, Member: method,
		Signature: sig, Args: append(append([]any{}, args...), options),
		Flags: dbuswire.FlagAllowInteractiveAuthorization,
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("rdesk: portal %s.%s: %w", iface, method, err)
	}
	if h, ok := reply.Body[0].(dbuswire.ObjectPath); !ok || h != path {
		// Portals before version 0.9 used another path; the token's
		// path is the only one listened to.
		return nil, fmt.Errorf("%w: portal çok eski (istek yolu farklı)", ErrUnsupported)
	}
	wait, cancel := context.WithTimeout(ctx, portalUserTimeout)
	defer cancel()
	for {
		select {
		case <-wait.Done():
			return nil, fmt.Errorf("%w: portal yanıt vermedi (%s)", ErrPortalDenied, method)
		case m, ok := <-sub.C:
			if !ok {
				return nil, errors.New("rdesk: portal bağlantısı kapandı")
			}
			if m.Sender != s.owner || len(m.Body) != 2 {
				continue
			}
			code, _ := m.Body[0].(uint32)
			switch code {
			case 0:
				return variantMap(m.Body[1]), nil
			case 1:
				return nil, ErrPortalDenied
			default:
				return nil, fmt.Errorf("rdesk: portal %s başarısız (kod %d)", method, code)
			}
		}
	}
}

// openPipeWire asks for the PipeWire connection and connects the
// streams.
func (s *portalSession) openPipeWire(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, portalCallTimeout)
	m, err := s.bus.Call(cctx, portalBus, portalPath, portalScreenCast, "OpenPipeWireRemote", "oa{sv}", s.handle, map[string]dbuswire.Variant{})
	cancel()
	if err != nil {
		return fmt.Errorf("rdesk: OpenPipeWireRemote: %w", err)
	}
	defer m.CloseFiles()
	idx, ok := m.Body[0].(dbuswire.UnixFD)
	if !ok || int(idx) >= len(m.Files) {
		return errors.New("rdesk: portal PipeWire tanımlayıcısı vermedi")
	}
	nodes := make([]uint32, len(s.streams))
	for i, st := range s.streams {
		nodes[i] = st.node
	}
	// openPipeWire takes its own copy of the descriptor.
	pw, err := openPipeWire(m.Files[idx], nodes)
	if err != nil {
		return err
	}
	s.pw = pw
	deadline := time.Now().Add(firstFrameWait)
	for time.Now().Before(deadline) {
		if all := s.frameSizes(); !slicesHasZero(all) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil // sizes fall back to the portal's logical ones
}

func slicesHasZero(ps []image.Point) bool {
	for _, p := range ps {
		if p.X <= 0 || p.Y <= 0 {
			return true
		}
	}
	return false
}

func (s *portalSession) frameSizes() []image.Point {
	out := make([]image.Point, len(s.streams))
	for i := range s.streams {
		out[i] = s.pw.size(i)
	}
	return out
}

func (s *portalSession) monitors() []Monitor { return waylandLayout(s.streams, s.frameSizes()) }

// waylandCapturer reads the portal's PipeWire streams.
type waylandCapturer struct {
	s    *portalSession
	tmp  []byte
	once sync.Once
}

func (c *waylandCapturer) Monitors() ([]Monitor, error) { return c.s.monitors(), nil }

func (c *waylandCapturer) Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	if r.Empty() || r.Dx() > maxDim || r.Dy() > maxDim {
		return nil, ErrScreenUnavailable
	}
	if dst == nil || dst.Rect.Dx() != r.Dx() || dst.Rect.Dy() != r.Dy() {
		dst = image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	} else {
		clear(dst.Pix)
	}
	got := false
	for i, m := range c.s.monitors() {
		part := m.Bounds.Intersect(r)
		if part.Empty() {
			continue
		}
		var size image.Point
		var err error
		c.tmp, size, err = c.s.pw.frame(i, c.tmp)
		if err != nil {
			return nil, err
		}
		if size.X <= 0 || size.Y <= 0 {
			continue
		}
		part = part.Intersect(image.Rectangle{Min: m.Bounds.Min, Max: m.Bounds.Min.Add(size)})
		for y := part.Min.Y; y < part.Max.Y; y++ {
			so := ((y-m.Bounds.Min.Y)*size.X + (part.Min.X - m.Bounds.Min.X)) * 4
			do := dst.PixOffset(part.Min.X-r.Min.X, y-r.Min.Y)
			copy(dst.Pix[do:do+part.Dx()*4], c.tmp[so:so+part.Dx()*4])
		}
		got = true
	}
	if !got {
		return nil, ErrScreenUnavailable
	}
	return dst, nil
}

func (c *waylandCapturer) Close() error {
	c.once.Do(c.s.release)
	return nil
}

// waylandInjector sends input through the RemoteDesktop portal. Events
// are sent without waiting for a reply, like XTEST requests.
type waylandInjector struct {
	s       *portalSession
	mu      sync.Mutex
	buttons uint8
	once    sync.Once
}

func (in *waylandInjector) notify(member string, sig dbuswire.Signature, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), portalCallTimeout)
	defer cancel()
	_, err := in.s.bus.Do(ctx, dbuswire.Call{
		Destination: portalBus, Path: portalPath, Interface: portalRemote, Member: member,
		Signature: sig, Args: append([]any{in.s.handle, map[string]dbuswire.Variant{}}, args...),
		Flags: dbuswire.FlagNoReplyExpected,
	})
	return err
}

func (in *waylandInjector) Pointer(x, y int, buttons uint8) error {
	node, lx, ly, ok := pointerTarget(in.s.streams, in.s.monitors(), x, y)
	if !ok {
		return ErrScreenUnavailable
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := in.notify("NotifyPointerMotionAbsolute", "oa{sv}udd", node, lx, ly); err != nil {
		return err
	}
	for _, b := range []struct {
		bit  uint8
		code int32
	}{{ButtonLeft, btnLeft}, {ButtonRight, btnRight}, {ButtonMiddle, btnMiddle}} {
		was, now := in.buttons&b.bit != 0, buttons&b.bit != 0
		if was == now {
			continue
		}
		state := portalKeyReleased
		if now {
			state = portalKeyPressed
		}
		if err := in.notify("NotifyPointerButton", "oa{sv}iu", b.code, state); err != nil {
			return err
		}
	}
	in.buttons = buttons
	return nil
}

func (in *waylandInjector) Wheel(dx, dy int) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	// Wayland axes grow down and right; rdesk's dy grows up.
	if dy != 0 {
		if err := in.notify("NotifyPointerAxisDiscrete", "oa{sv}ui", portalAxisVert, int32(-clampSteps(dy))); err != nil {
			return err
		}
	}
	if dx != 0 {
		if err := in.notify("NotifyPointerAxisDiscrete", "oa{sv}ui", portalAxisHoriz, int32(clampSteps(dx))); err != nil {
			return err
		}
	}
	return nil
}

func clampSteps(v int) int { return min(max(v, -32), 32) }

func (in *waylandInjector) Key(usage uint16, down bool) error {
	code, ok := hidToEvdev[usage]
	if !ok {
		return fmt.Errorf("rdesk: bilinmeyen tuş %#x", usage)
	}
	state := portalKeyReleased
	if down {
		state = portalKeyPressed
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.notify("NotifyKeyboardKeycode", "oa{sv}iu", code, state)
}

func (in *waylandInjector) Text(s string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, r := range s {
		sym := int32(runeKeysym(r))
		if err := in.notify("NotifyKeyboardKeysym", "oa{sv}iu", sym, portalKeyPressed); err != nil {
			return err
		}
		if err := in.notify("NotifyKeyboardKeysym", "oa{sv}iu", sym, portalKeyReleased); err != nil {
			return err
		}
	}
	return nil
}

func (in *waylandInjector) Close() error {
	in.once.Do(in.s.release)
	return nil
}
