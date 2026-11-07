//go:build windows

package winapp

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateProcessWithTokenW cannot pass standard handles, and any process can
// read a command line, a low-integrity one included. So the elevated tray
// hands the one-time link to the window it started over a named pipe. The
// name is public; the link goes only to the connection whose process is the
// child just created, and low-integrity processes cannot open the pipe.
//
// Limit (same as #645): a same-user medium-integrity process can still read
// the window process's memory; no check from outside can rule that out.

const (
	linkPipePrefix = `\\.\pipe\openscale-panel-`
	maxPipedLink   = 16 << 10
	// linkPipeOutbound is PIPE_ACCESS_OUTBOUND.
	linkPipeOutbound = 0x00000002
	// linkPipeRejectRemote is PIPE_REJECT_REMOTE_CLIENTS.
	linkPipeRejectRemote = 0x00000008
	// securitySqosAnonymous is SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS:
	// the pipe's server learns nothing usable about the window's token.
	securitySqosAnonymous = 0x00100000
	linkPipeClientWait    = windowStartGrace
)

var (
	errLinkPipeChildGone = errors.New("pencere süreci bağlantı adresini almadan çıktı")
	errLinkPipeTimeout   = errors.New("pencere süreci bağlantı adresini zamanında almadı")
)

// linkPipe is the server end of the pipe.
type linkPipe struct {
	name   string
	handle windows.Handle
}

// newLinkPipe creates a pipe with a random name that reader can read from
// and nobody below medium integrity can open. Only administrators can add
// another instance, so the name cannot be taken over.
func newLinkPipe(reader *windows.SID) (*linkPipe, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + reader.String() + ")S:(ML;;NWNR;;;ME)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	name := linkPipePrefix + hex.EncodeToString(random[:])
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateNamedPipe(p,
		linkPipeOutbound|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|linkPipeRejectRemote,
		1, maxPipedLink, 0, 0, &sa)
	if err != nil {
		return nil, err
	}
	return &linkPipe{name: name, handle: h}, nil
}

func (p *linkPipe) close() { _ = windows.CloseHandle(p.handle) }

// serve gives link to the first connection from process pid; any other
// connection is dropped without a byte. proc, when set, ends the wait if
// that process exits.
func (p *linkPipe) serve(pid uint32, link string, proc windows.Handle, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := p.accept(proc, deadline); err != nil {
			return err
		}
		var client uint32
		if err := windows.GetNamedPipeClientProcessId(p.handle, &client); err == nil && client == pid {
			return p.write(link, proc, deadline)
		}
		// SECURITY FIX: CWE-200 Same-user processes can connect; only the
		// window process gets the ticket.
		if err := windows.DisconnectNamedPipe(p.handle); err != nil {
			return err
		}
	}
}

func (p *linkPipe) accept(proc windows.Handle, deadline time.Time) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := windows.Overlapped{HEvent: ev}
	switch err := windows.ConnectNamedPipe(p.handle, &ov); {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case errors.Is(err, windows.ERROR_IO_PENDING):
		return p.waitIO(&ov, proc, deadline)
	default:
		return err
	}
}

func (p *linkPipe) write(link string, proc windows.Handle, deadline time.Time) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := windows.Overlapped{HEvent: ev}
	// The newline ends the read: the tray keeps the pipe open while it waits
	// to see whether the window came up.
	switch err := windows.WriteFile(p.handle, []byte(link+"\n"), nil, &ov); {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_IO_PENDING):
		return p.waitIO(&ov, proc, deadline)
	default:
		return err
	}
}

// waitIO waits for overlapped I/O, cancelling it at the deadline or when
// proc exits.
func (p *linkPipe) waitIO(ov *windows.Overlapped, proc windows.Handle, deadline time.Time) error {
	handles := []windows.Handle{ov.HEvent}
	if proc != 0 {
		handles = append(handles, proc)
	}
	fail := errLinkPipeTimeout
	if left := time.Until(deadline); left > 0 {
		ev, err := windows.WaitForMultipleObjects(handles, false, uint32(left/time.Millisecond))
		switch {
		case err != nil:
			fail = err
		case ev == windows.WAIT_OBJECT_0:
			var n uint32
			return windows.GetOverlappedResult(p.handle, ov, &n, false)
		case ev == windows.WAIT_OBJECT_0+1:
			fail = errLinkPipeChildGone
		}
	}
	var n uint32
	_ = windows.CancelIoEx(p.handle, ov)
	_ = windows.GetOverlappedResult(p.handle, ov, &n, true)
	return fail
}

// prepareShellWindowStart returns the pipe for link and the command line of
// a window process run with another token. The command line never carries
// link.
func prepareShellWindowStart(exe, link string, reader *windows.SID) (*linkPipe, string, error) {
	if _, err := validateLoopbackURL(link); err != nil {
		return nil, "", err
	}
	pipe, err := newLinkPipe(reader)
	if err != nil {
		return nil, "", err
	}
	line := windows.EscapeArg(exe) + " panel-window --title " + windows.EscapeArg(DisplayName()) + " --link-pipe " + windows.EscapeArg(pipe.name)
	return pipe, line, nil
}

// validLinkPipeName accepts only names newLinkPipe makes, so the flag cannot
// open any other file or pipe.
func validLinkPipeName(name string) bool {
	suffix, ok := strings.CutPrefix(name, linkPipePrefix)
	if !ok || len(suffix) != 32 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

// ReadPanelLinkPipe reads the one-time link the tray gives this process.
func ReadPanelLinkPipe(name string) (string, error) {
	if !validLinkPipeName(name) {
		return "", errors.New("geçersiz bağlantı kanalı adı")
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(linkPipeClientWait)
	var h windows.Handle
	for {
		h, err = windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, securitySqosAnonymous, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			return "", fmt.Errorf("bağlantı kanalı açılamadı: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	line, err := bufio.NewReader(io.LimitReader(f, maxPipedLink)).ReadString('\n')
	if err != nil {
		// A dropped connection ends here without a line.
		return "", fmt.Errorf("bağlantı kanalı adres vermedi: %w", err)
	}
	return strings.TrimSuffix(line, "\n"), nil
}
