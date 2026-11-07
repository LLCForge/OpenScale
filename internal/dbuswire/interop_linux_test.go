//go:build linux

package dbuswire

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestInteropDBusDaemon runs the client against a private dbus-daemon
// (OPENSCALE_DBUS_INTEROP=1; needs the dbus-daemon program). Nothing
// outside the test's temporary folder is touched.
func TestInteropDBusDaemon(t *testing.T) {
	if os.Getenv("OPENSCALE_DBUS_INTEROP") == "" {
		t.Skip("OPENSCALE_DBUS_INTEROP=1 ile çalışır")
	}
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon yok")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "bus")
	conf := filepath.Join(dir, "bus.conf")
	cfg := `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=` + sock + `</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`
	if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--nopidfile")
	cmd.Stderr = os.Stderr
	// The daemon dies with the test even when the test crashes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ep := Endpoint{Path: sock}
	svc, err := Dial(ctx, ep, Options{UnixFD: true})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	cli, err := Dial(ctx, ep, Options{UnixFD: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if !svc.UnixFD() {
		t.Error("dbus-daemon NEGOTIATE_UNIX_FD kabul etmedi")
	}
	if r, err := svc.RequestName(ctx, "org.openscale.Test", NameFlagDoNotQueue); err != nil || r != NameReplyPrimaryOwner {
		t.Fatalf("RequestName: %v %v", r, err)
	}
	err = svc.Export("/org/openscale/Test", &Interface{
		Name: "org.openscale.Test",
		Methods: []Method{{Name: "Echo", In: "sa{sv}", Out: "sv", Handler: func(c *MethodCall) ([]any, error) {
			return []any{strings.ToUpper(c.Body[0].(string)), MakeVariant(c.Sender)}, nil
		}}},
		Properties: []Property{{Name: "Answer", Sig: "i", Get: func() any { return int32(42) }}},
		Signals:    []SignalDef{{Name: "Ping", Sig: "s"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := cli.Call(ctx, "org.openscale.Test", "/org/openscale/Test", "org.openscale.Test", "Echo", "sa{sv}", "çağrı", map[string]Variant{"k": MakeVariant(uint32(1))})
	if err != nil {
		t.Fatal(err)
	}
	if m.Body[0] != "ÇAĞRI" || m.Body[1].(Variant).Value != cli.UniqueName() {
		t.Fatalf("Echo: %v", m.Body)
	}
	m, err = cli.Call(ctx, "org.openscale.Test", "/org/openscale/Test", PropertiesInterface, "Get", "ss", "org.openscale.Test", "Answer")
	if err != nil || m.Body[0].(Variant).Value != int32(42) {
		t.Fatalf("Get: %v %v", m, err)
	}
	m, err = cli.Call(ctx, "org.openscale.Test", "/", IntrospectableInterface, "Introspect", "")
	if err != nil || !strings.Contains(m.Body[0].(string), `<node name="org"/>`) {
		t.Fatalf("Introspect: %v %v", m, err)
	}
	if _, err := cli.Call(ctx, "org.openscale.Test", "/org/openscale/Test", "org.openscale.Test", "Nope", ""); err == nil {
		t.Fatal("bilinmeyen yöntem hata vermedi")
	}
	owner, err := cli.NameOwner(ctx, "org.openscale.Test")
	if err != nil || owner != svc.UniqueName() {
		t.Fatalf("NameOwner %q %v", owner, err)
	}
	m, err = cli.Call(ctx, BusName, BusPath, BusInterface, "GetConnectionUnixUser", "s", owner)
	if err != nil || m.Body[0] != uint32(os.Getuid()) {
		t.Fatalf("GetConnectionUnixUser: %v %v", m, err)
	}
	sub, err := cli.Subscribe(ctx, Match{Sender: owner, Path: "/org/openscale/Test", Interface: "org.openscale.Test", Member: "Ping"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Emit("/org/openscale/Test", "org.openscale.Test", "Ping", "s", "selam"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-sub.C:
		if s.Body[0] != "selam" {
			t.Fatalf("sinyal %v", s.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sinyal gelmedi")
	}
	sub.Close()

	// A reply that carries a file descriptor (like OpenPipeWireRemote).
	raw, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rr := bufio.NewReader(raw)
	res, err := authenticate(raw, rr, strconv.Itoa(os.Getuid()), true)
	if err != nil || !res.unixFD {
		t.Fatalf("raw auth: %v %+v", err, res)
	}
	hello, _ := (&Message{Type: TypeMethodCall, Serial: 1, Destination: BusName, Path: BusPath, Interface: BusInterface, Member: "Hello"}).marshal()
	if _, err := raw.Write(hello); err != nil {
		t.Fatal(err)
	}
	var rawName string
	for rawName == "" {
		hm, err := readMessage(rr)
		if err != nil {
			t.Fatal(err)
		}
		if hm.Type == TypeMethodReturn && hm.ReplySerial == 1 {
			rawName = hm.Body[0].(string)
		}
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	go func() {
		for {
			cm, err := readMessage(rr)
			if err != nil {
				return
			}
			if cm.Type != TypeMethodCall || cm.Member != "OpenRemote" {
				continue
			}
			reply := &Message{Type: TypeMethodReturn, Serial: 2, ReplySerial: cm.Serial, Destination: cm.Sender, Signature: "h", Body: []any{UnixFD(0)}, UnixFDs: 1}
			data, err := reply.marshalFDs(true)
			if err != nil {
				t.Error(err)
				return
			}
			_, _, err = raw.(*net.UnixConn).WriteMsgUnix(data, syscall.UnixRights(int(pw.Fd())), nil)
			if err != nil {
				t.Error(err)
			}
			_ = pw.Close()
			return
		}
	}()
	m, err = cli.Call(ctx, rawName, "/x", "org.openscale.Raw", "OpenRemote", "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.CloseFiles()
	if len(m.Files) != 1 || m.Body[0] != UnixFD(0) {
		t.Fatalf("tanımlayıcı gelmedi: %+v", m)
	}
	// The pipe's write end arrived: writing through it reaches pr.
	go func() { _, _ = m.Files[0].Write([]byte("pw")) }()
	buf := make([]byte, 2)
	_ = pr.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(pr, buf); err != nil || string(buf) != "pw" {
		t.Fatalf("tanımlayıcı çalışmıyor: %v %q", err, buf)
	}
}
