package rdesk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"image"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// MonitorPrimary asks the server for its primary monitor.
const MonitorPrimary = -2

const (
	pingInterval            = 20 * time.Second
	defaultClientHandshake  = maxConsentTimeout + 15*time.Second
	clientReadIdleTolerance = 2 * readTimeout
)

// ErrSessionEnded is returned once the server has ended the session.
var ErrSessionEnded = errors.New("rdesk: oturum sona erdi")

// DialOptions configures a client session.
type DialOptions struct {
	// Mode is ModeView (default) or ModeControl.
	Mode Mode
	// Monitor is a monitor index, MonitorAll or MonitorPrimary.
	Monitor int
	// MaxFPS lowers the server's frame rate ceiling; 0 keeps it.
	MaxFPS int
	// Scale fixes the downscale factor (1, 2 or 4); 0 lets the server
	// adapt it to the link.
	Scale int
	// OnClipboard receives the remote clipboard text in control sessions.
	// It runs on the receiving goroutine and must return quickly.
	OnClipboard func(text string)
	// Clipboard turns clipboard sharing on when the session opens (#122);
	// it is off by default and can be changed with SetClipboard.
	Clipboard bool
	// HandshakeTimeout bounds the wait for the server's answer, which
	// includes the on-screen approval (default 2m15s).
	HandshakeTimeout time.Duration
	// Credentials answers a device that asks for one of its operating
	// system accounts (ADR-0198). nil fails such a session with
	// ErrLoginRequired.
	Credentials CredentialsFunc
}

// Client is one remote desktop session.
type Client struct {
	conn net.Conn
	br   *bufio.Reader
	w    *wire
	opts DialOptions
	wmu  sync.Mutex
	ext  clientExt
	// version is the protocol version the server accepted (2 or 3).
	version uint8
	v3      clientV3

	mu        sync.Mutex
	monitors  []Monitor
	desktop   Desktop
	canvas    *image.RGBA
	frameCh   chan struct{} // closed and replaced after every frame
	frames    uint64        // complete frames received
	delivered uint64        // frames count at the last NextFrame
	err       error

	done    chan struct{}
	closing chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

// Dial opens a session with the server at addr.
func Dial(ctx context.Context, addr netip.AddrPort, opts DialOptions) (*Client, error) {
	if opts.Mode == 0 {
		opts.Mode = ModeView
	}
	if !opts.Mode.Valid() || !validScale(opts.Scale, true) || opts.MaxFPS < 0 || opts.MaxFPS > 255 {
		return nil, errors.New("rdesk: geçersiz oturum seçenekleri")
	}
	if opts.Monitor < MonitorPrimary || opts.Monitor >= maxMonitors {
		return nil, errors.New("rdesk: geçersiz monitör")
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = defaultClientHandshake
	}
	// Newest version first; an older server refuses it before asking
	// anyone, and the next attempt speaks the version before it
	// (ADR-0146, ADR-0198).
	var c *Client
	var err error
	for _, v := range []uint8{ProtocolVersionLogin, ProtocolVersionExt, ProtocolVersionE2E} {
		c, err = dialVersion(ctx, addr, opts, v)
		if !errors.Is(err, errVersionRejected) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	c.wg.Add(3)
	go c.readLoop()
	go c.pingLoop()
	go c.statsLoop()
	if opts.Clipboard && opts.Mode == ModeControl {
		// The answer arrives asynchronously; a refusal leaves sharing off.
		_ = c.sendExt(msgClipboardMode, extClipboard, 1)
	}
	return c, nil
}

func dialVersion(ctx context.Context, addr netip.AddrPort, opts DialOptions, version uint8) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("rdesk: bağlanılamadı: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	c, err := handshake(ctx, conn, opts, version)
	if !stop() || err != nil {
		_ = conn.Close()
		if err == nil || ctx.Err() != nil {
			err = errors.Join(ctx.Err(), err)
		}
		return nil, err
	}
	return c, nil
}

func handshake(ctx context.Context, conn net.Conn, opts DialOptions, version uint8) (*Client, error) {
	_ = conn.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
	mon := opts.Monitor
	if mon == MonitorPrimary {
		mon = 0xfe
	}
	h := hello{version: version, mode: opts.Mode, monitor: mon, maxFPS: opts.MaxFPS, scale: opts.Scale}
	priv, err := newE2EKey()
	if err != nil {
		return nil, err
	}
	helloMsg := h.encodeHelloVersion(version, priv.PublicKey().Bytes())
	if _, err := conn.Write(helloMsg); err != nil {
		return nil, fmt.Errorf("rdesk: başlangıç gönderilemedi: %w", err)
	}
	br := bufio.NewReaderSize(conn, 256<<10)
	w := &wire{br: br}
	t, p, err := readMsg(br, maxServerMsg)
	if err != nil {
		return nil, fmt.Errorf("rdesk: sunucu yanıt vermedi: %w", err)
	}
	code := ""
	if t == msgKex {
		if len(p) != e2eKeyLen {
			return nil, ErrProtocol
		}
		keys, err := deriveE2E(priv, p, helloMsg[headerLen:], p)
		if err != nil {
			return nil, err
		}
		w.rx, w.tx, code = keys.s2c, keys.c2s, keys.code
		if t, p, err = w.read(maxServerMsg); err != nil {
			return nil, fmt.Errorf("rdesk: sunucu yanıt vermedi: %w", err)
		}
		if t == msgLoginRequired {
			// The device wants an operating system account (ADR-0198).
			if t, p, err = clientLogin(ctx, w, conn, opts, code, p); err != nil {
				return nil, err
			}
		}
	}
	if t != msgWelcome {
		return nil, ErrProtocol
	}
	status, reason, err := decodeWelcome(p)
	if err != nil {
		return nil, err
	}
	if status == statusBadRequest && version >= ProtocolVersionExt && code == "" {
		return nil, errVersionRejected
	}
	if err := statusError(status, reason); err != nil {
		return nil, err
	}
	if code == "" {
		// An accepted session without the key exchange is a downgrade
		// (#130); refusals may come before it in plaintext.
		return nil, fmt.Errorf("%w: sunucu uçtan uca şifrelemeyi kullanmadı", ErrProtocol)
	}
	_ = conn.SetDeadline(time.Time{})
	c := &Client{conn: conn, br: br, w: w, opts: opts, version: version, frameCh: make(chan struct{}), done: make(chan struct{}), closing: make(chan struct{})}
	c.ext.init(code, reason == welcomeRecording)
	c.v3.init()
	return c, nil
}

// Mode returns the session's mode.
func (c *Client) Mode() Mode { return c.opts.Mode }

// Monitors returns the server's monitors as last reported.
func (c *Client) Monitors() []Monitor {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.monitors)
}

// Desktop returns the current image geometry.
func (c *Client) Desktop() Desktop {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.desktop
}

// Err returns why the session ended, or nil while it runs.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// NextFrame returns a copy of the whole image as soon as a complete frame
// has arrived that an earlier NextFrame call has not returned. The first
// call returns the first frame, which is always complete.
func (c *Client) NextFrame(ctx context.Context) (*image.RGBA, error) {
	for {
		c.mu.Lock()
		if c.frames > c.delivered && c.canvas != nil {
			c.delivered = c.frames
			img := image.NewRGBA(c.canvas.Rect)
			copy(img.Pix, c.canvas.Pix)
			c.mu.Unlock()
			return img, nil
		}
		ch := c.frameCh
		c.mu.Unlock()
		select {
		case <-ch:
		case <-c.done:
			return nil, c.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close ends the session.
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.closing)
		_ = c.conn.Close()
	})
	c.wg.Wait()
	return nil
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	defer close(c.done)
	defer func() { _ = c.conn.Close() }()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(clientReadIdleTolerance))
		t, p, err := c.w.read(maxServerMsg)
		if err != nil {
			select {
			case <-c.closing:
				c.fail(ErrSessionEnded)
			default:
				c.fail(fmt.Errorf("%w: %w", ErrSessionEnded, err))
			}
			return
		}
		c.v3.rxBytes.Add(uint64(len(p) + headerLen))
		if err := c.handle(t, p); err != nil {
			c.fail(err)
			c.v3.abort(err)
			return
		}
	}
}

func (c *Client) handle(t msgType, p []byte) error {
	switch t {
	case msgMonitors:
		ms, err := decodeMonitors(p)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.monitors = ms
		c.mu.Unlock()
	case msgDesktop:
		dk, err := decodeDesktop(p)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.desktop = dk
		if c.canvas == nil || c.canvas.Rect.Dx() != dk.Width || c.canvas.Rect.Dy() != dk.Height {
			c.canvas = image.NewRGBA(image.Rect(0, 0, dk.Width, dk.Height))
		}
		c.mu.Unlock()
	case msgTiles:
		c.mu.Lock()
		canvas := c.canvas
		var err error
		if canvas == nil {
			err = ErrProtocol
		} else {
			_, err = applyTiles(canvas, p)
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
	case msgFrameEnd:
		seq, err := decodeSeq(p)
		if err != nil {
			return err
		}
		if err := c.write(encodeSeq(msgAck, seq)); err != nil {
			return err
		}
		c.mu.Lock()
		c.frames++
		close(c.frameCh)
		c.frameCh = make(chan struct{})
		c.mu.Unlock()
	case msgClipboard:
		if c.opts.Mode != ModeControl {
			return ErrProtocol
		}
		s, err := decodeText(p, maxClipboardBytes)
		if err != nil {
			return err
		}
		if c.ext.clipOn.Load() && c.opts.OnClipboard != nil {
			c.opts.OnClipboard(s)
		}
	case msgExtStatus:
		return c.handleExtStatus(p)
	case msgKeepalive:
		if len(p) != 0 {
			return ErrProtocol
		}
	case msgEchoReply, msgFileListing, msgFileChunk, msgFileDone:
		if c.version < ProtocolVersionExt {
			return fmt.Errorf("%w: sürüm 3 iletisi", ErrProtocol)
		}
		return c.handleV3(t, p)
	case msgBye:
		d := dec{b: p}
		code := d.u8()
		reason := d.str8(maxReasonBytes)
		if code == byeNormal || reason == "" {
			return ErrSessionEnded
		}
		return fmt.Errorf("%w: %s", ErrSessionEnded, reason)
	default:
		return fmt.Errorf("%w: bilinmeyen ileti %#x", ErrProtocol, uint8(t))
	}
	return nil
}

func (c *Client) pingLoop() {
	defer c.wg.Done()
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if c.write(encodeMsg(msgPing, nil)) != nil {
				return
			}
		}
	}
}

func (c *Client) write(msg []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.conn.Write(c.w.seal(msg))
	return err
}

var errViewOnly = errors.New("rdesk: izleme oturumunda girdi gönderilemez")

func (c *Client) control(msg []byte) error {
	if c.opts.Mode != ModeControl {
		return errViewOnly
	}
	return c.write(msg)
}

// SendPointer moves the remote pointer to (x, y) in image pixels and sets
// the button state.
func (c *Client) SendPointer(x, y int, buttons uint8) error {
	return c.control(pointerEvent{x: x, y: y, buttons: buttons & (ButtonLeft | ButtonRight | ButtonMiddle)}.encode())
}

// SendWheel scrolls by whole notches (each between -100 and 100).
func (c *Client) SendWheel(dx, dy int) error { return c.control(encodeWheel(dx, dy)) }

// SendKey presses or releases the key with the given USB HID usage.
func (c *Client) SendKey(usage uint16, down bool) error { return c.control(encodeKey(usage, down)) }

// SendText types text on the remote device.
func (c *Client) SendText(s string) error {
	if len(s) > maxTextBytes {
		return errors.New("rdesk: metin çok uzun")
	}
	return c.control(encodeMsg(msgText, []byte(s)))
}

// SendClipboard sets the remote clipboard text.
func (c *Client) SendClipboard(s string) error {
	if len(s) > maxClipboardBytes {
		return errors.New("rdesk: pano metni çok uzun")
	}
	if !c.ext.clipOn.Load() {
		return errClipboardOff
	}
	return c.control(encodeMsg(msgClipboard, []byte(s)))
}

// SelectMonitor switches to monitor i or, with MonitorAll, to every
// monitor together.
func (c *Client) SelectMonitor(i int) error {
	if i != MonitorAll && (i < 0 || i >= maxMonitors) {
		return errors.New("rdesk: geçersiz monitör")
	}
	return c.write(encodeMsg(msgSelectMonitor, []byte{monitorByte(i)}))
}

// SetQuality lowers the frame rate ceiling (0 keeps the server's) and
// fixes the scale (1, 2 or 4) or makes it adaptive (0).
func (c *Client) SetQuality(maxFPS, scale int) error {
	if maxFPS < 0 || maxFPS > 255 || !validScale(scale, true) {
		return errors.New("rdesk: geçersiz kalite")
	}
	return c.write(encodeQuality(maxFPS, scale))
}

// Activity tells the server the viewer is being used, which resets its
// idle timeout. Viewers call it on local user interaction.
func (c *Client) Activity() error { return c.write(encodeMsg(msgActivity, nil)) }

// Refresh asks for a complete frame.
func (c *Client) Refresh() error { return c.write(encodeMsg(msgRefresh, nil)) }

// Snapshot opens a view session, waits for the first complete frame at
// full resolution and closes the session.
func Snapshot(ctx context.Context, addr netip.AddrPort, monitor int) (*image.RGBA, []Monitor, error) {
	c, err := Dial(ctx, addr, DialOptions{Mode: ModeView, Monitor: monitor, Scale: 1, MaxFPS: minFPS})
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	img, err := c.NextFrame(ctx)
	if err != nil {
		return nil, nil, err
	}
	return img, c.Monitors(), nil
}
