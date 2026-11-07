//go:build windows

package winapp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows side of "Send with OpenScale" (f3_sendto.go).

const (
	sendToLinkName  = "OpenScale.lnk"
	sendToArg       = "send-to"
	sendToMaxMsg    = 64 << 10
	sendToWait      = 5 * time.Second
	sendToIOTimeout = 30 * time.Second

	pipeRejectRemote     = 0x00000008
	securitySqosPresent  = 0x00100000
	securityImpersonate  = 0x00020000 // SECURITY_IMPERSONATION << 16
	processQueryLimited  = 0x1000
	fileAttributeReparse = 0x400
)

// sendToPipePrefix is followed by the session number; tests change it.
var sendToPipePrefix = `\\.\pipe\openscale-sendto-`

var (
	modAdvapi32F3                 = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClnt  = modAdvapi32F3.NewProc("ImpersonateNamedPipeClient")
	errSendToServerNotOpenScale   = errors.New("gönderme kanalı OpenScale programına ait değil")
	errSendToCallerNotOpenScale   = errors.New("istek OpenScale programından gelmedi")
	errSendToCallerOtherSession   = errors.New("istek başka bir oturumdan geldi")
	errSendToBadRequest           = errors.New("geçersiz gönderme isteği")
	errSendToImpersonationFailure = errors.New("dosyalar çağıranın haklarıyla açılamadı")
)

// SendToShortcutPath is %APPDATA%\Microsoft\Windows\SendTo\OpenScale.lnk
// of the signed-in user.
func SendToShortcutPath() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_SendTo, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, sendToLinkName), nil
}

// EnsureSendToShortcut creates or refreshes the Send to entry that starts
// exe with "send-to". The tray calls it at start; a failure only leaves
// the menu entry out.
func EnsureSendToShortcut(exe string) error {
	p, err := SendToShortcutPath()
	if err != nil {
		return err
	}
	desc := Tr("Dosyaları OpenScale ile uçtan uca şifreli gönder", "Send files end-to-end encrypted with OpenScale")
	return withShellLink(func(link, file *comObject) error {
		if err := link.callString(idxSLSetPath, exe); err != nil {
			return err
		}
		if err := link.callString(idxSLSetArguments, sendToArg); err != nil {
			return err
		}
		if err := link.callString(idxSLSetWorkingDirectory, filepath.Dir(exe)); err != nil {
			return err
		}
		if err := link.callString(idxSLSetDescription, desc); err != nil {
			return err
		}
		icon, err := windows.UTF16PtrFromString(exe)
		if err != nil {
			return err
		}
		if err := link.call(idxSLSetIconLocation, uintptr(unsafe.Pointer(icon)), 0); err != nil {
			return err
		}
		if err := link.call(idxSLSetShowCmd, swShowMinNoActive); err != nil {
			return err
		}
		target, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		return file.call(idxPFSave, uintptr(unsafe.Pointer(target)), 1)
	})
}

// RemoveSendToShortcut deletes the Send to entry (uninstall); best effort.
func RemoveSendToShortcut() {
	if p, err := SendToShortcutPath(); err == nil {
		_ = os.Remove(p)
	}
}

func sendToPipeName() (string, error) {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		return "", err
	}
	return sendToPipePrefix + strconv.FormatUint(uint64(sid), 10), nil
}

type sendToRequest struct {
	Version int      `json:"v"`
	Paths   []string `json:"paths"`
}

type sendToReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > sendToMaxMsg {
		return errSendToBadRequest
	}
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	_, err = w.Write(append(msg, b...))
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > sendToMaxMsg {
		return errSendToBadRequest
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// processImage returns the full image path of process pid.
func processImage(pid uint32) (string, error) {
	h, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// isOpenScaleImage reports whether p is the installed program or this
// very program.
func isOpenScaleImage(p string) bool {
	p = filepath.Clean(p)
	if strings.EqualFold(p, filepath.Join(InstallDir(), "openscale.exe")) {
		return true
	}
	self, err := os.Executable()
	return err == nil && strings.EqualFold(p, filepath.Clean(self))
}

// SendToTray hands checked paths to the running tray. It refuses a pipe
// that another program created.
func SendToTray(paths []string) error {
	name, err := sendToPipeName()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(sendToWait)
	var h windows.Handle
	for {
		h, err = windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			securitySqosPresent|securityImpersonate, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
				return ErrSendToTrayMissing
			}
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		return err
	}
	img, err := processImage(pid)
	if err != nil || !isOpenScaleImage(img) {
		return errSendToServerNotOpenScale
	}
	if err := writeFrame(f, sendToRequest{Version: 1, Paths: paths}); err != nil {
		return err
	}
	var rep sendToReply
	if err := readFrame(f, &rep); err != nil {
		return err
	}
	if !rep.OK {
		if rep.Error == "" {
			rep.Error = "tepsi isteği kabul etmedi"
		}
		return errors.New(rep.Error)
	}
	return nil
}

// SendToFile is a file the tray opened for a Send to request, with the
// caller's rights. The handler owns File and must close it.
type SendToFile struct {
	Name string
	Size int64
	File *os.File
}

// ServeSendTo answers Send to requests of this session until ctx ends.
// handle gets the opened files of each request and runs on its own
// goroutine; the caller is told at once whether the files were accepted.
func ServeSendTo(ctx context.Context, handle func([]SendToFile)) error {
	name, err := sendToPipeName()
	if err != nil {
		return err
	}
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	// SYSTEM and administrators full; this user read and write; nothing
	// below medium integrity; no network clients.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + user.User.Sid.String() + ")S:(ML;;NW;;;ME)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	// One instance, created first: nobody else can serve this name while
	// the tray runs.
	h, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|pipeRejectRemote, 1, sendToMaxMsg, sendToMaxMsg, 0, &sa)
	if err != nil {
		return fmt.Errorf("gönderme kanalı açılamadı: %w", err)
	}
	defer windows.CloseHandle(h)
	stop := context.AfterFunc(ctx, func() {
		// Wake ConnectNamedPipe with a connection of our own.
		if c, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
			_ = windows.CloseHandle(c)
		}
	})
	defer stop()
	var mySession uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &mySession)
	for ctx.Err() == nil {
		err := windows.ConnectNamedPipe(h, nil)
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if ctx.Err() != nil {
			_ = windows.DisconnectNamedPipe(h)
			return nil
		}
		serveSendToConn(h, mySession, handle)
		_ = windows.FlushFileBuffers(h)
		_ = windows.DisconnectNamedPipe(h)
	}
	return nil
}

// pipeConn reads and writes the connected pipe without owning the handle.
type pipeConn struct{ h windows.Handle }

func (c pipeConn) Read(b []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(c.h, b, &n, nil)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return int(n), err
}

func (c pipeConn) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(c.h, b, &n, nil)
	return int(n), err
}

func serveSendToConn(h windows.Handle, mySession uint32, handle func([]SendToFile)) {
	conn := pipeConn{h: h}
	reply := func(err error) {
		if err != nil {
			_ = writeFrame(conn, sendToReply{Error: err.Error()})
			return
		}
		_ = writeFrame(conn, sendToReply{OK: true})
	}
	var pid, session uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return
	}
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil || session != mySession {
		reply(errSendToCallerOtherSession)
		return
	}
	if img, err := processImage(pid); err != nil || !isOpenScaleImage(img) {
		reply(errSendToCallerNotOpenScale)
		return
	}
	done := make(chan error, 1)
	var req sendToRequest
	go func() { done <- readFrame(conn, &req) }()
	select {
	case err := <-done:
		if err != nil || req.Version != 1 {
			reply(errSendToBadRequest)
			return
		}
	case <-time.After(sendToIOTimeout):
		_ = windows.DisconnectNamedPipe(h)
		<-done
		return
	}
	infos, err := CheckSendToArgs(req.Paths, os.Lstat)
	if err != nil {
		reply(err)
		return
	}
	files, err := openAsCaller(h, infos)
	if err != nil {
		reply(err)
		return
	}
	reply(nil)
	go handle(files)
}

// openAsCaller opens every file with the pipe client's token and checks
// the handles. Impersonation belongs to the OS thread, so the thread is
// locked; if reverting fails the thread is never unlocked and the runtime
// retires it with the goroutine.
func openAsCaller(h windows.Handle, infos []SendToFileInfo) ([]SendToFile, error) {
	type result struct {
		files []SendToFile
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if r, _, _ := procImpersonateNamedPipeClnt.Call(uintptr(h)); r == 0 {
			runtime.UnlockOSThread()
			ch <- result{err: errSendToImpersonationFailure}
			return
		}
		files, err := openChecked(infos)
		if rerr := windows.RevertToSelf(); rerr != nil {
			for _, f := range files {
				_ = f.File.Close()
			}
			ch <- result{err: errSendToImpersonationFailure}
			return // the thread stays locked and dies with the goroutine
		}
		runtime.UnlockOSThread()
		ch <- result{files: files, err: err}
	}()
	r := <-ch
	return r.files, r.err
}

func openChecked(infos []SendToFileInfo) ([]SendToFile, error) {
	var out []SendToFile
	fail := func(err error) ([]SendToFile, error) {
		for _, f := range out {
			_ = f.File.Close()
		}
		return nil, err
	}
	var total int64
	for _, in := range infos {
		p, err := windows.UTF16PtrFromString(in.Path)
		if err != nil {
			return fail(&SendToArgError{Path: in.Path, Reason: "yol geçersiz"})
		}
		fh, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
		if err != nil {
			return fail(&SendToArgError{Path: in.Path, Reason: "dosya bu hesapla okunamıyor"})
		}
		f := os.NewFile(uintptr(fh), in.Path)
		if t, err := windows.GetFileType(fh); err != nil || t != windows.FILE_TYPE_DISK {
			_ = f.Close()
			return fail(&SendToArgError{Path: in.Path, Reason: "yalnızca diskteki dosyalar gönderilebilir"})
		}
		var bi windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(fh, &bi); err != nil {
			_ = f.Close()
			return fail(&SendToArgError{Path: in.Path, Reason: "dosya bilgisi okunamadı"})
		}
		size := int64(bi.FileSizeHigh)<<32 | int64(bi.FileSizeLow)
		switch {
		case bi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
			_ = f.Close()
			return fail(&SendToArgError{Path: in.Path, Reason: "klasörler gönderilemez"})
		case bi.FileAttributes&fileAttributeReparse != 0:
			_ = f.Close()
			return fail(&SendToArgError{Path: in.Path, Reason: "bağlantılar gönderilemez"})
		case bi.NumberOfLinks != 1:
			_ = f.Close()
			return fail(&SendToArgError{Path: in.Path, Reason: "birden çok sabit bağlantısı olan dosyalar gönderilemez"})
		case size > MaxSendToFile:
			_ = f.Close()
			return fail(&SendToArgError{Path: in.Path, Reason: "dosya 2 GiB sınırını aşıyor"})
		}
		total += size
		if total > MaxSendToTotal {
			_ = f.Close()
			return fail(ErrSendToTooLarge)
		}
		out = append(out, SendToFile{Name: in.Name, Size: size, File: f})
	}
	return out, nil
}

var (
	procF3GetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	procF3FreeConsole           = windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole")
)

// DetachOwnConsole lets go of a console window that only this process
// uses (Explorer started it); a terminal's console is kept.
func DetachOwnConsole() bool {
	var ids [2]uint32
	n, _, _ := procF3GetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), 2)
	if n != 1 {
		return false
	}
	_, _, _ = procF3FreeConsole.Call()
	return true
}

// ShowMessage shows a message box (an error box when isError).
func ShowMessage(text string, isError bool) {
	t, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	caption, _ := windows.UTF16PtrFromString("OpenScale")
	flags := uint32(windows.MB_OK | windows.MB_ICONINFORMATION)
	if isError {
		flags = windows.MB_OK | windows.MB_ICONERROR
	}
	_, _ = windows.MessageBox(0, t, caption, flags|windows.MB_SETFOREGROUND)
}
