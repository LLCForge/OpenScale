package rdesk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// P24 additions to the session (ADR-0103): per-session clipboard opt-in
// (#122), screen blanking and local input lock (#119), remote restart
// (#129) and the end-to-end layer and recording hooks (#130, #128).

// Client to server (control sessions only).
const (
	// msgClipboardMode turns clipboard sharing on (1) or off (0).
	msgClipboardMode msgType = 0x0d
	// msgLocalLock sets the screen blanking and input lock bits.
	msgLocalLock msgType = 0x0e
	// msgPower asks for a restart (powerRestart, powerSafeMode).
	msgPower msgType = 0x0f
)

// Server to client: the answer to one of the requests above.
const msgExtStatus msgType = 0x89

// Request kinds in msgExtStatus.
const (
	extClipboard uint8 = 1
	extLocalLock uint8 = 2
	extPower     uint8 = 3
)

// Local lock bits.
const (
	lockBlank uint8 = 1 << 0
	lockInput uint8 = 1 << 1
)

// Power requests.
const (
	powerRestart  uint8 = 1
	powerSafeMode uint8 = 2
)

// welcomeRecording is the reason text of an accepting welcome when the
// session is recorded; version 1 clients ignore it.
const welcomeRecording = "recording"

// powerTimeout bounds the Power callback.
const powerTimeout = 15 * time.Second

// Bounds of the drain after the last message of a graceful end.
const (
	endDrainTimeout = time.Second
	endDrainLimit   = 1 << 20
	// endWriteStall bounds the wait for a frame write in progress.
	endWriteStall = 2 * time.Second
)

// LockState is the screen blanking and local input lock of a session.
type LockState struct {
	// Blank covers the physical screen with a notice; the overlay is
	// excluded from capture so the viewer still sees the desktop.
	Blank bool
	// Input blocks the local keyboard and mouse; injected input from the
	// session still works. Ctrl+Alt+Del always reaches the system.
	Input bool
}

func (l LockState) bits() uint8 {
	var b uint8
	if l.Blank {
		b |= lockBlank
	}
	if l.Input {
		b |= lockInput
	}
	return b
}

// LocalLock blanks the physical screen and blocks local input (#119).
type LocalLock interface {
	// Set applies st; notice is shown on the blanked screen so the person
	// at the device always sees that a session is running.
	Set(st LockState, notice string) error
	// Close releases everything; it must restore the screen and input.
	Close() error
}

// PowerRequest is a remote restart request (#129).
type PowerRequest struct {
	// Peer is the requesting device.
	Peer string
	// SafeMode asks for a restart into safe mode with networking.
	SafeMode bool
}

// PowerFunc restarts the device. It must schedule the restart and return
// quickly; the session ends after it returns nil.
type PowerFunc func(ctx context.Context, req PowerRequest) error

type sessionExt struct {
	started   atomic.Bool
	clipOn    atomic.Bool
	lock      LocalLock
	lockState LockState
	powerBusy atomic.Bool
}

// release restores the local screen and input; called once the read
// goroutine has ended.
func (e *sessionExt) release() {
	if e.lock != nil {
		_ = e.lock.Close()
		e.lock = nil
	}
	e.lockState = LockState{}
}

func (s *Server) versionAllowed(v uint8) bool {
	return v == ProtocolVersionE2E || v == ProtocolVersionExt || v == ProtocolVersionLogin || (v == ProtocolVersion && s.cfg.AllowLegacyV1)
}

// ControlSessionFrom reports whether a running control session comes from
// remote and names its device. The service uses it to accept files
// dropped onto the viewer (filesend, ADR-0031) without a second prompt
// while the session lasts; the files rule is still required.
func (s *Server) ControlSessionFrom(remote netip.Addr) (string, bool) {
	remote = remote.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	for sess := range s.sessions {
		if sess.remote == remote && sess.mode == ModeControl && sess.ext.started.Load() {
			return sess.peer, true
		}
	}
	return "", false
}

// writeRaw writes one message outside the frame loop, sealed when the
// end-to-end layer is on.
func (sess *session) writeRaw(msg []byte) {
	sess.wmu.Lock()
	defer sess.wmu.Unlock()
	writeRaw(sess.conn, sess.w.seal(msg))
}

func (sess *session) event(kind EventKind, at time.Time, reason string) SessionEvent {
	ev := SessionEvent{
		Kind: kind, ID: sess.id, Peer: sess.peer, Mode: sess.mode, Unattended: !sess.consented,
		Time: at, Reason: reason, Code: sess.code, Recording: sess.rec != nil,
	}
	if kind != EventEnd {
		ev.Clipboard = sess.ext.clipOn.Load()
		ev.LocalLock = sess.ext.lockState
	}
	return ev
}

func encodeExtStatus(kind uint8, ok bool, reason string) []byte {
	var b uint8
	if ok {
		b = 1
	}
	return encodeMsg(msgExtStatus, appendStr8([]byte{kind, b}, reason, maxReasonBytes))
}

func decodeExtStatus(p []byte) (uint8, bool, string, error) {
	d := dec{b: p}
	kind, ok := d.u8(), d.u8()
	reason := d.str8(maxReasonBytes)
	if err := d.end(); err != nil {
		return 0, false, "", err
	}
	if kind < extClipboard || kind > extPower || ok > 1 {
		return 0, false, "", ErrProtocol
	}
	return kind, ok == 1, reason, nil
}

func (sess *session) status(kind uint8, ok bool, reason string) {
	_, _ = sess.send(encodeExtStatus(kind, ok, reason))
}

// handleExt serves the P24 requests of a control session; it runs on the
// read goroutine.
func (sess *session) handleExt(t msgType, p []byte) error {
	if len(p) != 1 {
		return ErrProtocol
	}
	switch t {
	case msgClipboardMode:
		if p[0] > 1 {
			return ErrProtocol
		}
		sess.setClipboard(p[0] == 1)
	case msgLocalLock:
		if p[0]&^(lockBlank|lockInput) != 0 {
			return ErrProtocol
		}
		sess.setLocalLock(LockState{Blank: p[0]&lockBlank != 0, Input: p[0]&lockInput != 0})
	case msgPower:
		if p[0] != powerRestart && p[0] != powerSafeMode {
			return ErrProtocol
		}
		sess.power(PowerRequest{Peer: sess.peer, SafeMode: p[0] == powerSafeMode})
	}
	return nil
}

func (sess *session) notifyChange() {
	sess.srv.cfg.Indicator(sess.event(EventChange, time.Now(), ""))
}

// setClipboard turns clipboard sharing on or off for this session (#122).
func (sess *session) setClipboard(on bool) {
	cfg := &sess.srv.cfg
	if on && cfg.DisableClipboard {
		sess.status(extClipboard, false, "pano paylaşımı bu cihazda kapalı")
		return
	}
	if on && !sess.sessionHas(ChanClipboard) {
		// #670: the clipboard is a separate permission.
		sess.status(extClipboard, false, "pano paylaşımına kural izin vermiyor")
		return
	}
	if on {
		sess.sum.mark(true, false)
	}
	if on && sess.clip == nil {
		clip, err := cfg.NewClipboard()
		if err != nil {
			sess.status(extClipboard, false, "pano bu sistemde desteklenmiyor")
			return
		}
		sess.clip = clip
		sess.bg.Go(sess.clipboardLoop)
	}
	// The answer goes first: a clipboard change sent by the frame side
	// before the viewer learns that sharing is on would be dropped there.
	// The viewer's next message is read only after the switch below.
	sess.status(extClipboard, on, "")
	if sess.ext.clipOn.Swap(on) != on {
		sess.srv.log.Info("uzak masaüstü pano paylaşımı", "peer", sess.peer, "on", on)
		sess.notifyChange()
	}
}

// setLocalLock applies screen blanking and the local input lock (#119).
// Any failure releases both, so the device is never left half locked.
func (sess *session) setLocalLock(st LockState) {
	cfg := &sess.srv.cfg
	if st == sess.ext.lockState {
		sess.status(extLocalLock, true, "")
		return
	}
	if st != (LockState{}) && cfg.NewLocalLock == nil {
		sess.status(extLocalLock, false, "ekran karartma ve giriş kilidi bu cihazda kapalı")
		return
	}
	if st != (LockState{}) && !sess.sessionHas(ChanCurtain) {
		// #666: the privacy curtain needs its own permission.
		sess.status(extLocalLock, false, "gizlilik perdesine kural izin vermiyor")
		return
	}
	if st != (LockState{}) {
		sess.sum.mark(false, true)
	}
	if sess.ext.lock == nil && st != (LockState{}) {
		l, err := cfg.NewLocalLock()
		if err != nil {
			sess.srv.log.Warn("ekran karartma açılamadı", "peer", sess.peer, "err", err)
			sess.status(extLocalLock, false, lockErrText(err))
			return
		}
		sess.ext.lock = l
	}
	ok, reason := true, ""
	if sess.ext.lock != nil {
		notice := fmt.Sprintf("Bu bilgisayar şu anda %s cihazından uzaktan kullanılıyor.", sess.peer)
		if err := sess.ext.lock.Set(st, notice); err != nil {
			sess.srv.log.Warn("ekran karartma uygulanamadı; kilit kaldırıldı", "peer", sess.peer, "err", err)
			_ = sess.ext.lock.Set(LockState{}, "")
			st, ok, reason = LockState{}, false, lockErrText(err)
		}
	}
	if sess.ext.lockState != st {
		sess.ext.lockState = st
		sess.srv.log.Info("uzak masaüstü yerel kilit", "peer", sess.peer, "blank", st.Blank, "input", st.Input)
		sess.notifyChange()
	}
	sess.status(extLocalLock, ok, reason)
}

func lockErrText(err error) string {
	if errors.Is(err, ErrUnsupported) {
		return "ekran karartma bu sistemde desteklenmiyor"
	}
	return "ekran karartma uygulanamadı"
}

// power asks the service to restart the device (#129) and ends the
// session when the restart is scheduled.
func (sess *session) power(req PowerRequest) {
	cfg := &sess.srv.cfg
	if cfg.Power == nil {
		sess.status(extPower, false, "uzaktan yeniden başlatma bu cihazda kapalı")
		return
	}
	if !sess.ext.powerBusy.CompareAndSwap(false, true) {
		sess.status(extPower, false, "yeniden başlatma zaten istendi")
		return
	}
	sess.srv.log.Warn("uzaktan yeniden başlatma istendi", "peer", sess.peer, "safe_mode", req.SafeMode)
	ctx, cancel := context.WithTimeout(sess.ctx, powerTimeout)
	err := cfg.Power(ctx, req)
	cancel()
	if err != nil {
		sess.ext.powerBusy.Store(false)
		sess.srv.log.Warn("uzaktan yeniden başlatma başarısız", "peer", sess.peer, "err", err)
		reason := "yeniden başlatılamadı"
		if errors.Is(err, ErrUnsupported) {
			reason = "bu istek bu sistemde desteklenmiyor"
		}
		sess.status(extPower, false, reason)
		return
	}
	sess.status(extPower, true, "")
	// power runs on the read goroutine, so the drain has no competing reader.
	sess.finish(byeShutdown, "cihaz yeniden başlatılıyor", true)
}

// drainBeforeClose shuts the write side and discards what the peer still
// sends until it hangs up, the timeout passes or endDrainLimit bytes were
// read. Closing a socket with unread data sends a reset, and Windows then
// drops the answer the peer has not read yet. A peer cannot hold the session
// open: both the time and the amount are bounded.
func drainBeforeClose(c net.Conn, timeout time.Duration) {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok || cw.CloseWrite() != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	_, _ = io.CopyN(io.Discard, c, endDrainLimit)
}
