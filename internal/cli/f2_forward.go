package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/pkg/client"
)

// openscale forward <local-port> <device>:<port> (#815): a local port
// forward through the tunnel, like "ssh -L" without an SSH server. The
// listener is bound to 127.0.0.1 only, so nothing on the LAN can use it.
// The target must be a device of the signed document on this computer;
// each connection is dialled to its tunnel address, so the target's own
// packet filter applies the signed rules exactly as for any other
// connection from this device. Ctrl+C stops it.

func init() {
	registerCommands(command{"forward", "Yerel portu tünel üzerinden bir cihazın portuna yönlendirir: <yerel-port> <cihaz>:<port> (yalnızca 127.0.0.1; Ctrl+C ile kapanır)", cmdForward})
}

// forwardTarget is a resolved forward destination.
type forwardTarget struct {
	device string
	addr   netip.AddrPort
}

// parseForwardArgs checks "<local-port> <device>:<port>".
func parseForwardArgs(args []string) (uint16, string, uint16, error) {
	if len(args) != 2 {
		return 0, "", 0, usageError("kullanım: openscale forward <yerel-port> <cihaz>:<port>")
	}
	local, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 16)
	if err != nil {
		return 0, "", 0, usageError("yerel port 0 ile 65535 arasında bir sayı olmalı (0: boş bir port)")
	}
	name, portText, ok := strings.Cut(strings.TrimSpace(args[1]), ":")
	name = strings.ToLower(strings.TrimSpace(name))
	if !ok || name == "" || strings.Contains(portText, ":") {
		return 0, "", 0, usageError("hedef <cihaz>:<port> biçiminde olmalı, ör. nas:80")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, "", 0, usageError("hedef port 1 ile 65535 arasında olmalı")
	}
	return uint16(local), name, uint16(port), nil
}

// resolveForwardTarget finds name in the signed document. A tunnel IP or
// a name outside the document is refused: the target must be a member.
func resolveForwardTarget(doc *trust.Document, self, name string, port uint16) (forwardTarget, error) {
	if doc == nil {
		return forwardTarget{}, errors.New("ağ belgesi okunamadı; komutu yönetici olarak çalıştırın veya --data-dir/--state-dir verin")
	}
	name = strings.TrimSuffix(strings.TrimSuffix(name, "."), "."+doc.DNSDomain)
	d, ok := doc.DeviceByName(name)
	if !ok {
		return forwardTarget{}, deviceNotFound(doc, name)
	}
	if d.Name == self {
		return forwardTarget{}, usageError("%s bu cihazın kendisi; yerel bir port için yönlendirme gerekmez", d.Name)
	}
	if !d.IPv4.IsValid() {
		return forwardTarget{}, fmt.Errorf("%s cihazının tünel adresi yok", d.Name)
	}
	return forwardTarget{device: d.Name, addr: netip.AddrPortFrom(d.IPv4, port)}, nil
}

// loopbackResolver answers client.Forward's identity check for the local
// listener: only connections from this computer's loopback address count,
// as this device. Anything else is no device and is closed.
type loopbackResolver struct{ self string }

func (r loopbackResolver) WhoIs(_ context.Context, addr string) (client.WhoIsResult, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Unmap().IsLoopback() {
		return client.WhoIsResult{Query: addr}, nil
	}
	return client.WhoIsResult{Query: addr, Device: &client.Device{Name: r.self, Self: true}}, nil
}

// listenForward opens the local listener on 127.0.0.1 only.
func listenForward(ctx context.Context, port uint16) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp4", netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port).String())
}

// runForward copies connections from ln to target until ctx ends.
func runForward(ctx context.Context, ln net.Listener, target string, self string) error {
	return client.Forward(ctx, ln, target, loopbackResolver{self: self}, func(d client.Device) bool { return d.Self })
}

func cmdForward(env *Env, args []string) error {
	fs := newFlagSet(env, "forward")
	rf := addRemoteFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale forward [seçenekler] <yerel-port> <cihaz>:<port>")
		fmt.Fprintln(env.Stderr, "Örnek: openscale forward 8080 nas:80  ->  http://127.0.0.1:8080 nas cihazının 80 portuna gider.")
		fmt.Fprintln(env.Stderr, "Dinleyici yalnızca 127.0.0.1'dedir; hedefteki erişim kuralları aynen geçerlidir.")
		fs.PrintDefaults()
	}
	// Flags may come before or after the two arguments.
	var pos []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return usageError("%v", err)
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	localPort, name, port, err := parseForwardArgs(pos)
	if err != nil {
		return err
	}
	rc := loadRemoteContext(env, rf)
	target, err := resolveForwardTarget(rc.doc, rc.self, name, port)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	ln, err := listenForward(ctx, localPort)
	if err != nil {
		return err
	}
	self := rc.self
	if self == "" {
		self = "bu-cihaz"
	}
	fmt.Fprintf(env.Stdout, "%s -> %s (%s) yönlendiriliyor. Kapatmak için Ctrl+C.\n", ln.Addr(), target.device, target.addr)
	fmt.Fprintln(env.Stdout, "Bağlantı kurulamıyorsa hedefte bu cihazdan o porta izin veren bir kural olmalı.")
	if err := runForward(ctx, ln, target.addr.String(), self); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Yönlendirme kapatıldı.")
	return nil
}
