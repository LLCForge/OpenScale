package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/openscale/openscale/internal/panel"
)

// The terminal interface (#551): status, peers, exit node choice and the
// event stream over SSH without the panel. It is drawn with plain ANSI
// escape sequences (no library) and talks only to the local API, like
// the other diagnostics commands. Changing the exit node needs a second
// key press to confirm.

const (
	tuiRefresh   = 2 * time.Second
	tuiMaxEvents = 200
)

// tuiSource is what the interface reads and changes; the local API in
// use, a fake in tests.
type tuiSource interface {
	Status(ctx context.Context) (panel.DiagStatus, error)
	Events(ctx context.Context, since uint64) (panel.EventStreamReply, error)
	SetExit(ctx context.Context, name string) error
}

type apiTUISource struct {
	env *Env
	c   *localClient
}

func (s apiTUISource) Status(ctx context.Context) (panel.DiagStatus, error) {
	var st panel.DiagStatus
	err := s.c.call(ctx, "GET", panel.LocalAPIPrefix+"/status", nil, &st)
	return st, err
}

func (s apiTUISource) Events(ctx context.Context, since uint64) (panel.EventStreamReply, error) {
	var rep panel.EventStreamReply
	err := s.c.call(ctx, "GET", fmt.Sprintf("%s/events/poll?since=%d&wait=0", panel.LocalAPIPrefix, since), nil, &rep)
	return rep, err
}

func (s apiTUISource) SetExit(ctx context.Context, name string) error {
	return s.c.call(ctx, "POST", panel.LocalAPIPrefix+"/prefs", map[string]any{"set": map[string]string{"exit-node": name}}, nil)
}

// tuiModel is the screen's state.
type tuiModel struct {
	status   panel.DiagStatus
	err      string
	events   []panel.StreamEvent
	since    uint64
	selected int
	showLog  bool
	// pending is the exit node waiting for confirmation ("-" clears).
	pending string
	message string
	width   int
	height  int
}

// Actions of a key.
type tuiAction int

const (
	tuiNone tuiAction = iota
	tuiQuit
	tuiApplyExit
	tuiRefreshNow
)

func (m *tuiModel) key(k string) tuiAction {
	if m.pending != "" {
		switch k {
		case "e", "y", "\r":
			return tuiApplyExit
		default:
			m.pending, m.message = "", "Vazgeçildi."
			return tuiNone
		}
	}
	switch k {
	case "q", "\x03", "\x1b":
		return tuiQuit
	case "j", "\x1b[B":
		if m.selected < len(m.status.Peers)-1 {
			m.selected++
		}
	case "k", "\x1b[A":
		if m.selected > 0 {
			m.selected--
		}
	case "l":
		m.showLog = !m.showLog
	case "r":
		return tuiRefreshNow
	case "x":
		if m.selected >= len(m.status.Peers) {
			return tuiNone
		}
		p := m.status.Peers[m.selected]
		if !p.ExitNode {
			m.message = p.Name + " bir çıkış düğümü değil."
			return tuiNone
		}
		m.pending = p.Name
		m.message = fmt.Sprintf("İnternet trafiği %s üzerinden çıksın mı? Onay: e, vazgeç: başka bir tuş", p.Name)
	case "n":
		if m.status.ExitNode == "" {
			m.message = "Çıkış düğümü zaten kullanılmıyor."
			return tuiNone
		}
		m.pending = "-"
		m.message = "Çıkış düğümü kapatılsın mı? Onay: e, vazgeç: başka bir tuş"
	}
	return tuiNone
}

func (m *tuiModel) setStatus(st panel.DiagStatus) {
	m.status, m.err = st, ""
	if m.selected >= len(st.Peers) {
		m.selected = max(0, len(st.Peers)-1)
	}
}

func (m *tuiModel) addEvents(rep panel.EventStreamReply) {
	m.events = append(m.events, rep.Events...)
	if len(m.events) > tuiMaxEvents {
		m.events = append(m.events[:0:0], m.events[len(m.events)-tuiMaxEvents:]...)
	}
	m.since = rep.Next
}

// clip cuts s to width runes and drops control characters, so text from
// the service cannot move the cursor or change the terminal.
func clip(s string, width int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = ' '
		}
		if n >= width {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func padRight(s string, width int) string {
	s = clip(s, width)
	if n := utf8.RuneCountInString(s); n < width {
		s += strings.Repeat(" ", width-n)
	}
	return s
}

// render draws the whole screen.
func (m *tuiModel) render(now time.Time) string {
	w := max(m.width, 40)
	h := max(m.height, 12)
	var lines []string
	add := func(s string) { lines = append(lines, clip(s, w)) }
	st := m.status
	state := "kapalı"
	switch {
	case st.Running && st.Connected:
		state = "bağlı"
	case st.Running:
		state = "çalışıyor, koordinatöre ulaşılamıyor"
	}
	self := "-"
	if st.Self != nil {
		self = st.Self.Name
	}
	exit := st.ExitNode
	if exit == "" {
		exit = "yok"
	}
	add(fmt.Sprintf("OpenScale  cihaz: %s  durum: %s  çıkış: %s  belge: %d", self, state, exit, st.DocumentVersion))
	if m.err != "" {
		add("Hata: " + m.err)
	} else if st.LastSyncError != "" {
		add("Eşitleme hatası: " + st.LastSyncError)
	} else {
		add("")
	}
	add(strings.Repeat("-", w))
	logRows := 0
	if m.showLog {
		logRows = max(3, (h-8)/2)
	}
	peerRows := max(1, h-7-logRows)
	add(fmt.Sprintf("  %-22s %-7s %-6s %-9s %10s %10s", "EŞ", "DURUM", "YOL", "GECİKME", "GELEN", "GİDEN"))
	start := 0
	if m.selected >= peerRows {
		start = m.selected - peerRows + 1
	}
	if len(st.Peers) == 0 {
		add("  (eş yok)")
	}
	for i := start; i < len(st.Peers) && i < start+peerRows; i++ {
		p := st.Peers[i]
		mark := "  "
		if i == m.selected {
			mark = "> "
		}
		on := "kapalı"
		if p.Online {
			on = "açık"
		}
		lat := "-"
		if p.LatencyMS != nil {
			lat = fmt.Sprintf("%.0f ms", *p.LatencyMS)
		}
		name := p.Name
		if p.ActiveExit {
			name += " (çıkış)"
		} else if p.ExitNode {
			name += " [ç]"
		}
		line := mark + padRight(name, 22) + " " + padRight(on, 7) + " " + padRight(p.Path, 6) + " " + padRight(lat, 9) + " " +
			fmt.Sprintf("%10s %10s", humanBytes(p.RxBytes), humanBytes(p.TxBytes))
		if i == m.selected {
			line = "\x1b[7m" + clip(line, w) + "\x1b[0m"
			lines = append(lines, line)
			continue
		}
		add(line)
	}
	if m.showLog {
		add(strings.Repeat("-", w))
		evs := m.events
		if len(evs) > logRows {
			evs = evs[len(evs)-logRows:]
		}
		for _, ev := range evs {
			add(fmt.Sprintf("%s %-8s %s", ev.At.In(now.Location()).Format("15:04:05"), ev.Severity, ev.Message))
		}
	}
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	add(strings.Repeat("-", w))
	if m.message != "" {
		add(m.message)
	} else {
		add("↑/↓ seç  x çıkış yap  n çıkışı kapat  l olaylar  r yenile  q çık")
	}
	var b strings.Builder
	b.WriteString("\x1b[H")
	for i, l := range lines {
		if i >= h {
			break
		}
		b.WriteString(l)
		b.WriteString("\x1b[K")
		if i < len(lines)-1 && i < h-1 {
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\x1b[J")
	return b.String()
}

// readKeys turns the terminal's bytes into keys; escape sequences of the
// arrow keys arrive in one read.
func readKeys(in io.Reader, keys chan<- string) {
	buf := make([]byte, 32)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			s := string(buf[:n])
			switch {
			case strings.HasPrefix(s, "\x1b[") && len(s) >= 3:
				keys <- s[:3]
			default:
				for _, r := range s {
					keys <- string(r)
				}
			}
		}
		if err != nil {
			close(keys)
			return
		}
	}
}

// runTUI draws and handles keys until q, Ctrl+C or ctx ends.
func runTUI(ctx context.Context, src tuiSource, in io.Reader, out io.Writer, size func() (int, int), now func() time.Time, refresh time.Duration) error {
	m := &tuiModel{}
	m.width, m.height = size()
	refreshAll := func() {
		cctx, cancel := context.WithTimeout(ctx, localCallTimeout)
		defer cancel()
		st, err := src.Status(cctx)
		if err != nil {
			m.err = describe(err)
			return
		}
		m.setStatus(st)
		if rep, err := src.Events(cctx, m.since); err == nil {
			m.addEvents(rep)
		}
	}
	// Start at the newest event: nothing old is replayed.
	if rep, err := src.Events(ctx, 0); err == nil {
		m.since = rep.Next
	}
	refreshAll()
	keys := make(chan string, 16)
	go readKeys(in, keys)
	t := time.NewTicker(refresh)
	defer t.Stop()
	draw := func() {
		m.width, m.height = size()
		_, _ = io.WriteString(out, m.render(now()))
	}
	draw()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			refreshAll()
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			switch m.key(k) {
			case tuiQuit:
				return nil
			case tuiRefreshNow:
				refreshAll()
			case tuiApplyExit:
				name := m.pending
				if name == "-" {
					name = ""
				}
				m.pending = ""
				cctx, cancel := context.WithTimeout(ctx, localCallTimeout)
				err := src.SetExit(cctx, name)
				cancel()
				switch {
				case err != nil:
					m.message = "Değiştirilemedi: " + describe(err)
				case name == "":
					m.message = "Çıkış düğümü kapatıldı."
				default:
					m.message = "Çıkış düğümü: " + name
				}
				refreshAll()
			}
		}
		draw()
	}
}

func cmdTUI(env *Env, args []string) error {
	fs := newFlagSet(env, "tui")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if env.IsTerminal == nil || !env.IsTerminal() {
		return errors.New("terminal arayüzü etkileşimli bir terminal ister; betikler için 'openscale status --json' kullanın")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	inFd := int(os.Stdin.Fd())
	outFd := int(os.Stdout.Fd())
	old, err := term.MakeRaw(inFd)
	if err != nil {
		return fmt.Errorf("terminal ham kipe alınamadı: %w", err)
	}
	restoreOut := enableANSI(outFd)
	out := env.Stdout
	_, _ = io.WriteString(out, "\x1b[?1049h\x1b[?25l")
	defer func() {
		_, _ = io.WriteString(out, "\x1b[?25h\x1b[?1049l")
		restoreOut()
		_ = term.Restore(inFd, old)
	}()
	size := func() (int, int) {
		w, h, err := term.GetSize(outFd)
		if err != nil {
			return 80, 24
		}
		return w, h
	}
	return runTUI(envContext(env), apiTUISource{env: env, c: c}, os.Stdin, out, size, env.Now, tuiRefresh)
}
