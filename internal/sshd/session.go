package sshd

import (
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxCommandLen = 32 << 10
	maxEnvVars    = 32
	maxEnvLen     = 4 << 10
	maxTermDim    = 1000
	outputDrain   = 2 * time.Second
	exitCodeFail  = 255
)

// errNoPTY is returned by startPTY on platforms without PTY support.
var errNoPTY = errors.New("bu platformda PTY desteklenmiyor")

// ptyParams holds the client's terminal request.
type ptyParams struct {
	term       string
	cols, rows uint32
}

// procRequest describes a process to start for a session.
type procRequest struct {
	acct    *account
	command string // empty starts an interactive shell
	env     []string
}

// process is a running session process.
type process interface {
	// wait blocks until the process exits and returns its exit code.
	wait() int
	// kill terminates the process and its descendants.
	kill()
	// resize changes the terminal size; a no-op without a PTY.
	resize(cols, rows uint32)
}

type ptyReqMsg struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

type windowChangeMsg struct {
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
}

type envMsg struct {
	Name  string
	Value string
}

type execMsg struct {
	Command string
}

type exitStatusMsg struct {
	Status uint32
}

func clampDim(v uint32, def uint32) uint32 {
	if v == 0 {
		return def
	}
	if v > maxTermDim {
		return maxTermDim
	}
	return v
}

// allowedClientEnv lists environment variables a client may set. Anything
// that changes program loading or shell start-up (PATH, LD_*, BASH_ENV, ...)
// is refused.
func allowedClientEnv(name string) bool {
	return name == "LANG" || name == "LANGUAGE" || name == "TZ" || name == "COLORTERM" ||
		(strings.HasPrefix(name, "LC_") && len(name) <= 32)
}

func validEnvValue(v string) bool {
	return len(v) <= maxEnvLen && !strings.ContainsAny(v, "\x00\n\r")
}

func (s *Server) handleSession(c *serverConn, nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	var (
		pty     *ptyParams
		env     []string
		proc    process
		term    ptyTerminal
		exited  = make(chan int, 1)
		outDone = make(chan struct{})
	)
	defer func() {
		if proc != nil {
			proc.kill()
		}
		if term != nil {
			_ = term.Close()
		}
	}()

	start := func(command string) bool {
		req := procRequest{acct: c.acct, command: command, env: env}
		if pty != nil {
			p, t, err := startPTY(req, *pty)
			if err == nil {
				proc, term = p, t
				go func() { _, _ = io.Copy(t, ch) }()
				go func() {
					_, _ = io.Copy(ch, t)
					close(outDone)
				}()
				go func() {
					code := p.wait()
					t.ProcessExited()
					exited <- code
				}()
				return true
			}
			if !errors.Is(err, errNoPTY) {
				s.log.Warn("SSH: PTY'li süreç başlatılamadı", "err", err)
				return false
			}
			// Fall back to a process without a terminal.
		}
		p, err := startPipes(req, ch, ch, ch.Stderr())
		if err != nil {
			s.log.Warn("SSH: süreç başlatılamadı", "err", err)
			return false
		}
		proc = p
		close(outDone) // startPipes' wait already flushes output
		go func() { exited <- p.wait() }()
		return true
	}

	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return
			}
			s.handleSessionRequest(c, req, &pty, &env, proc != nil, start, func(cols, rows uint32) {
				if proc != nil {
					proc.resize(cols, rows)
				}
			})
		case code := <-exited:
			select {
			case <-outDone:
			case <-time.After(outputDrain):
			}
			if code < 0 {
				code = exitCodeFail
			}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: uint32(code)}))
			_ = ch.CloseWrite()
			proc = nil
			return
		}
	}
}

func (s *Server) handleSessionRequest(c *serverConn, req *ssh.Request, pty **ptyParams, env *[]string,
	started bool, start func(string) bool, resize func(cols, rows uint32)) {
	reply := func(ok bool) {
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
	switch req.Type {
	case "pty-req":
		var m ptyReqMsg
		if started || ssh.Unmarshal(req.Payload, &m) != nil || len(m.Term) > 64 {
			reply(false)
			return
		}
		*pty = &ptyParams{term: m.Term, cols: clampDim(m.Cols, 80), rows: clampDim(m.Rows, 24)}
		reply(true)
	case "env":
		var m envMsg
		if started || ssh.Unmarshal(req.Payload, &m) != nil || len(*env) >= maxEnvVars ||
			!allowedClientEnv(m.Name) || !validEnvValue(m.Value) {
			reply(false)
			return
		}
		*env = append(*env, m.Name+"="+m.Value)
		reply(true)
	case "shell":
		if started {
			reply(false)
			return
		}
		if c.restr.restricted {
			// #669: a restricted account never gets a shell; a forced
			// command (one allowed command) runs instead, like ForceCommand.
			if len(c.restr.commands) != 1 {
				s.log.Info("SSH kabuğu reddedildi: komut izin listesi", "user", c.user)
				reply(false)
				return
			}
			reply(start(c.restr.commands[0]))
			return
		}
		reply(start(""))
	case "exec":
		var m execMsg
		if started || ssh.Unmarshal(req.Payload, &m) != nil || m.Command == "" ||
			len(m.Command) > maxCommandLen || strings.ContainsRune(m.Command, 0) {
			reply(false)
			return
		}
		if !c.restr.commandAllowed(m.Command) {
			s.log.Info("SSH komutu reddedildi: izin listesinde yok", "user", c.user)
			reply(false)
			return
		}
		s.log.Debug("SSH komutu", "user", c.user)
		reply(start(m.Command))
	case "window-change":
		var m windowChangeMsg
		if ssh.Unmarshal(req.Payload, &m) == nil {
			resize(clampDim(m.Cols, 80), clampDim(m.Rows, 24))
		}
		reply(true)
	default:
		// subsystem (sftp), x11-req, auth-agent-req@openssh.com, signal,
		// break and anything unknown are refused.
		reply(false)
	}
}

// ptyTerminal is the parent's side of a pseudo terminal.
type ptyTerminal interface {
	io.ReadWriter
	// ProcessExited is called when the process exits so the output reader
	// can drain the remaining output and finish.
	ProcessExited()
	// Close releases the terminal.
	Close() error
}

// cmdProcess adapts exec.Cmd to process for sessions without a PTY.
type cmdProcess struct {
	cmd      *exec.Cmd
	killOnce sync.Once
	killFn   func()
	waitOnce sync.Once
	code     int
	onExit   func()
}

func (p *cmdProcess) wait() int {
	p.waitOnce.Do(func() {
		err := p.cmd.Wait()
		p.code = 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				p.code = ee.ExitCode()
			} else {
				p.code = exitCodeFail
			}
		}
		if p.onExit != nil {
			p.onExit()
		}
	})
	return p.code
}

func (p *cmdProcess) kill() {
	p.killOnce.Do(func() {
		if p.killFn != nil {
			p.killFn()
		} else if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
	})
}

func (p *cmdProcess) resize(uint32, uint32) {}

// startPipes starts req without a terminal; output goes to stdout/stderr
// and stdin is fed from the channel.
func startPipes(req procRequest, stdin io.Reader, stdout, stderr io.Writer) (*cmdProcess, error) {
	cmd, err := buildCommand(req, false)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Do not let a lingering grandchild that inherited stdout keep the
	// session open forever after the main process exits.
	cmd.WaitDelay = outputDrain
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &cmdProcess{cmd: cmd}
	p.killFn, p.onExit = afterStart(cmd)
	go func() {
		_, _ = io.Copy(in, stdin)
		_ = in.Close()
	}()
	return p, nil
}

// errEOF is returned by terminals at end of output.
var errEOF = io.EOF

// sanitizeTerm keeps a client-supplied TERM value only when it is a plain
// terminal name.
func sanitizeTerm(t string) string {
	if t == "" || len(t) > 64 {
		return "xterm"
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '+') {
			return "xterm"
		}
	}
	return t
}
