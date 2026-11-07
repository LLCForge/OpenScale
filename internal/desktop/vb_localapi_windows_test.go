//go:build windows

package desktop

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/openscale/openscale/internal/peercred"
)

// TestLocalAPICheckCombinesAdminAndProgram (#645): the service's app
// token check is the elevation check plus the same-program check. A
// caller from this very program passes exactly when it is elevated, and
// an address outside loopback never passes.
func TestLocalAPICheckCombinesAdminAndProgram(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	srv := <-accepted
	defer srv.Close()
	remote, local := srv.RemoteAddr().String(), srv.LocalAddr().String()

	check := localAPICheck(slog.New(slog.NewTextHandler(io.Discard, nil)))
	adminErr := peercred.Policy{Admins: true}.Check(remote, local)
	if got := check(remote, local); (got == nil) != (adminErr == nil) {
		t.Fatalf("same program: check %v, admin check %v", got, adminErr)
	}
	if err := check("10.0.0.1:5", local); err == nil {
		t.Fatal("non-loopback caller accepted")
	}
}
