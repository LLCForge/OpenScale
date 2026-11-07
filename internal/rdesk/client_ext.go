package rdesk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Viewer side of the P24 additions (ADR-0103).

const extReplyTimeout = 20 * time.Second

var errClipboardOff = errors.New("rdesk: pano paylaşımı kapalı; önce SetClipboard(true)")

// ErrExtRefused is returned when the device refuses a clipboard, lock or
// restart request.
var ErrExtRefused = errors.New("rdesk: istek reddedildi")

type extReply struct {
	ok     bool
	reason string
}

type clientExt struct {
	code     string
	recorded bool
	clipOn   atomic.Bool
	lock     atomic.Uint32
	replies  [extPower + 1]chan extReply
}

func (e *clientExt) init(code string, recorded bool) {
	e.code, e.recorded = code, recorded
	for i := range e.replies {
		e.replies[i] = make(chan extReply, 1)
	}
}

// VerificationCode returns the end-to-end verification code (#130). The
// device shows the same code in its approval prompt and indicator; a
// different code means someone on the way replaced the keys.
func (c *Client) VerificationCode() string { return c.ext.code }

// Recorded reports whether the device records this session (#128).
func (c *Client) Recorded() bool { return c.ext.recorded }

// ClipboardShared reports whether clipboard sharing is on.
func (c *Client) ClipboardShared() bool { return c.ext.clipOn.Load() }

// LocalLock returns the screen blanking and input lock the device last
// confirmed.
func (c *Client) LocalLock() LockState {
	b := uint8(c.ext.lock.Load())
	return LockState{Blank: b&lockBlank != 0, Input: b&lockInput != 0}
}

func (c *Client) handleExtStatus(p []byte) error {
	kind, ok, reason, err := decodeExtStatus(p)
	if err != nil {
		return err
	}
	if c.opts.Mode != ModeControl {
		return ErrProtocol
	}
	if kind == extClipboard {
		c.ext.clipOn.Store(ok)
	}
	select {
	case c.ext.replies[kind] <- extReply{ok: ok, reason: reason}:
	default:
	}
	return nil
}

// sendExt drops a stale answer and sends one request.
func (c *Client) sendExt(t msgType, kind uint8, arg uint8) error {
	select {
	case <-c.ext.replies[kind]:
	default:
	}
	return c.control(encodeMsg(t, []byte{arg}))
}

func (c *Client) waitExt(ctx context.Context, kind uint8) (extReply, error) {
	ctx, cancel := context.WithTimeout(ctx, extReplyTimeout)
	defer cancel()
	select {
	case r := <-c.ext.replies[kind]:
		return r, nil
	case <-c.done:
		// The answer and the end of the session can arrive together; select
		// picks either, and an answer that was received counts.
		select {
		case r := <-c.ext.replies[kind]:
			return r, nil
		default:
		}
		return extReply{}, c.Err()
	case <-ctx.Done():
		return extReply{}, ctx.Err()
	}
}

func refused(r extReply) error {
	if r.reason == "" {
		return ErrExtRefused
	}
	return fmt.Errorf("%w: %s", ErrExtRefused, r.reason)
}

// SetClipboard turns clipboard sharing on or off for this session (#122).
func (c *Client) SetClipboard(ctx context.Context, on bool) error {
	var arg uint8
	if on {
		arg = 1
	}
	if err := c.sendExt(msgClipboardMode, extClipboard, arg); err != nil {
		return err
	}
	r, err := c.waitExt(ctx, extClipboard)
	if err != nil {
		return err
	}
	if r.ok != on || r.reason != "" {
		return refused(r)
	}
	return nil
}

// SetLocalLock blanks the device's physical screen and/or blocks its local
// keyboard and mouse while the session lasts (#119). The device must
// allow it; the blanked screen still names the viewing device.
func (c *Client) SetLocalLock(ctx context.Context, st LockState) error {
	if err := c.sendExt(msgLocalLock, extLocalLock, st.bits()); err != nil {
		return err
	}
	r, err := c.waitExt(ctx, extLocalLock)
	if err != nil {
		return err
	}
	if !r.ok {
		c.ext.lock.Store(0)
		return refused(r)
	}
	c.ext.lock.Store(uint32(st.bits()))
	return nil
}

// RequestRestart asks the device to restart, into safe mode with
// networking when safeMode is set (#129). On success the device ends the
// session; reconnect with DialRetry once it is back.
func (c *Client) RequestRestart(ctx context.Context, safeMode bool) error {
	arg := powerRestart
	if safeMode {
		arg = powerSafeMode
	}
	if err := c.sendExt(msgPower, extPower, arg); err != nil {
		return err
	}
	r, err := c.waitExt(ctx, extPower)
	if err != nil {
		return err
	}
	if !r.ok {
		return refused(r)
	}
	return nil
}

// DialRetry dials until a session opens or ctx ends, waiting every
// between attempts (at least 2 seconds). It retries only while the device
// is unreachable, busy or cannot show its screen yet (for example right
// after a restart, before anyone signs in); rule denials, refusals and
// protocol errors are returned at once so a person is never asked
// repeatedly.
func DialRetry(ctx context.Context, addr netip.AddrPort, opts DialOptions, every time.Duration) (*Client, error) {
	every = max(every, 2*time.Second)
	for {
		c, err := Dial(ctx, addr, opts)
		if err == nil {
			return c, nil
		}
		if !retryable(err) || ctx.Err() != nil {
			return nil, err
		}
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, errors.Join(ctx.Err(), err)
		case <-t.C:
		}
	}
}

func retryable(err error) bool {
	if errors.Is(err, ErrBusy) || errors.Is(err, ErrRemoteUnsupported) {
		return true
	}
	if errors.Is(err, ErrDenied) || errors.Is(err, ErrRefused) || errors.Is(err, ErrProtocol) {
		return false
	}
	var ne net.Error
	var oe *net.OpError
	return errors.As(err, &ne) || errors.As(err, &oe)
}
