package openscale

import (
	"errors"

	"golang.zx2c4.com/wireguard/conn"
)

// fdPeeker is implemented by wireguard-go's StdNetBind on Android.
type fdPeeker interface {
	PeekLookAtSocketFd4() (int, error)
	PeekLookAtSocketFd6() (int, error)
}

// protectBind keeps WireGuard's UDP sockets out of the VPN: after every
// Open it hands their descriptors to VpnService.protect. The app also
// excludes itself from its own VPN (ADR-0101), so this is the second
// layer that still holds if that exclusion is ever lost; a socket Android
// refuses to protect fails the Open instead of looping traffic into the
// tunnel.
type protectBind struct {
	conn.Bind
	protect func(fd int) bool
}

var errProtect = errors.New("Android WireGuard soketini VPN dışında tutmayı reddetti")

func (b *protectBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	p, ok := b.Bind.(fdPeeker)
	if !ok || b.protect == nil {
		return fns, actual, nil
	}
	for _, peek := range []func() (int, error){p.PeekLookAtSocketFd4, p.PeekLookAtSocketFd6} {
		fd, err := peek()
		if err != nil || fd < 0 {
			continue // that family has no socket (e.g. no IPv6)
		}
		if !b.protect(fd) {
			_ = b.Bind.Close()
			return nil, 0, errProtect
		}
	}
	return fns, actual, nil
}
