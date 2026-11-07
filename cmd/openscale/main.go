// Command openscale is the OpenScale command line.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/openscale/openscale/internal/cli"
	"github.com/openscale/openscale/internal/desktop"
	"github.com/openscale/openscale/internal/privsep"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

func main() {
	profile := hardenProcess(os.Args[1:])
	// The parsing helper (ADR-0233) is this program started by the service
	// with reduced rights; it serves its parent on stdin/stdout only and
	// never reaches the command line, the startup checks or any key.
	if len(os.Args) == 2 && os.Args[1] == privsep.HelperArg {
		os.Exit(privsep.RunHelper(privsep.HelperOptions{}))
	}
	// Program folder and self verification (#644, #607, g4_startup.go).
	if !startupChecks(profile, os.Stderr, time.Now()) {
		os.Exit(exitStartupBlocked)
	}
	applyMemoryProfile()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	stdin := bufio.NewReader(os.Stdin)
	env := &cli.Env{
		Ctx:    ctx,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Now:    time.Now,
		Random: rand.Reader,
		ReadSecret: func(prompt string) ([]byte, error) {
			// Separate-desktop prompt on Windows (#649, g4_startup.go).
			if b, ok, err := readSecretSecure(prompt); ok {
				return b, err
			}
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return b, err
		},
		ReadLine: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			line, err := stdin.ReadString('\n')
			if err != nil && line == "" {
				return "", err
			}
			return strings.TrimSpace(line), nil
		},
		IsTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		Hostname:   os.Hostname,
		DefaultStateDir: func() (string, error) {
			base, err := os.UserConfigDir()
			if err != nil {
				return "", err
			}
			if base == "" {
				return "", errors.New("user config directory is empty")
			}
			return filepath.Join(base, "OpenScale"), nil
		},
		Argon2: trust.DefaultArgon2,
	}
	desktop.Version = version.Display() // beta label (ADR-0193)
	args := withoutProcessSerial(os.Args[1:])
	// Double-clicking the program in Explorer, or opening OpenScale.app in
	// Finder, opens the desktop app instead of printing help into a
	// console that closes immediately.
	if len(args) == 0 && desktop.LaunchedByDoubleClick() {
		args = []string{"app"}
	}
	code := cli.Run(args, env)
	stop()
	os.Exit(code)
}

// withoutProcessSerial drops the "-psn_<n>_<n>" argument that older macOS
// versions give a program LaunchServices starts from an app bundle.
func withoutProcessSerial(args []string) []string {
	if len(args) == 1 && strings.HasPrefix(args[0], "-psn_") {
		return nil
	}
	return args
}
