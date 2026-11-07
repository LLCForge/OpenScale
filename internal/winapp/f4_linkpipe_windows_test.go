//go:build windows

package winapp

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	testPipeLink  = "http://127.0.0.1:8080/auth/ticket?t=gizli-bilet"
	testPipeEnv   = "OPENSCALE_TEST_LINK_PIPE"
	testPipeLabel = "alinan:"
)

// The child of TestLinkPipeGivesLinkOnlyToChild.
func TestHelperLinkPipeChild(t *testing.T) {
	name := os.Getenv(testPipeEnv)
	if name == "" {
		t.Skip("yardımcı süreç")
	}
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	link, err := ReadPanelLinkPipe(name)
	if err != nil {
		fmt.Println("hata:", err)
		return
	}
	fmt.Println(testPipeLabel + link)
}

// The audit's attacker can read process command lines: the ticket must not
// be on the command line of the window the elevated tray starts.
func TestShellWindowStartHidesTicket(t *testing.T) {
	pipe, line, err := prepareShellWindowStart(`C:\OpenScale\openscale.exe`, testPipeLink, selfSID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.close()
	if strings.Contains(line, "gizli-bilet") || strings.Contains(line, TicketPath) {
		t.Fatalf("bilet komut satırında: %s", line)
	}
	if !strings.Contains(line, pipe.name) {
		t.Fatalf("kanal adı komut satırında yok: %s", line)
	}
}

func TestLinkPipeGivesLinkOnlyToChild(t *testing.T) {
	// The tray keeps the pipe open while it waits for the window, which must
	// not hold the window up; and it may also close before the child read.
	t.Run("kanal açık kalır", func(t *testing.T) { testLinkPipe(t, false) })
	t.Run("kanal hemen kapanır", func(t *testing.T) { testLinkPipe(t, true) })
}

func testLinkPipe(t *testing.T, closeFirst bool) {
	pipe, err := newLinkPipe(selfSID(t))
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperLinkPipeChild$", "-test.v", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), testPipeEnv+"="+pipe.name)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		pipe.close()
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		pipe.close()
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	served := make(chan error, 1)
	go func() { served <- pipe.serve(uint32(cmd.Process.Pid), testPipeLink, 0, 20*time.Second) }()

	// This process is the same user, but not the window: it gets nothing.
	if got, err := ReadPanelLinkPipe(pipe.name); err == nil || strings.Contains(got, "gizli-bilet") {
		pipe.close()
		t.Fatalf("başka süreç bileti aldı: %q %v", got, err)
	}

	if _, err := stdin.Write([]byte("\n")); err != nil {
		pipe.close()
		t.Fatal(err)
	}
	err = <-served
	if closeFirst {
		pipe.close()
	} else {
		defer pipe.close()
	}
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("yardımcı: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), testPipeLabel+testPipeLink) {
		t.Fatalf("pencere süreci bileti alamadı:\n%s", out.String())
	}
}

func TestLinkPipeRefusesOtherNames(t *testing.T) {
	for _, name := range []string{"", `C:\Windows\win.ini`, linkPipePrefix, `\\.\pipe\baska`, linkPipePrefix + "zz"} {
		if _, err := ReadPanelLinkPipe(name); err == nil {
			t.Fatalf("%q kabul edildi", name)
		}
	}
}

func TestLinkPipeServeStopsAtDeadline(t *testing.T) {
	pipe, err := newLinkPipe(selfSID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.close()
	if err := pipe.serve(1, testPipeLink, 0, 50*time.Millisecond); err == nil {
		t.Fatal("bağlanan yokken serve başarılı döndü")
	}
}
