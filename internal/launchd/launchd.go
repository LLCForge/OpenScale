// Package launchd writes macOS launchd property lists for the OpenScale
// daemons (#159, ADR-0100): the device service and the boot-time kill
// switch restore. It only produces text; installing and controlling the
// jobs is done by the callers with /bin/launchctl.
package launchd

import (
	"encoding/xml"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
)

// DaemonDir is where system-wide launch daemons live. Files there must
// belong to root and not be writable by group or others, or launchd
// refuses them.
const DaemonDir = "/Library/LaunchDaemons"

// Job describes one launch daemon.
type Job struct {
	// Label is the reverse-DNS job name, e.g. com.openscale.device.
	Label string
	// Program is the absolute program path followed by its arguments.
	Program []string
	// Marker, when set, is written as an XML comment right after the
	// header, so uninstall can recognize files it wrote.
	Marker string
	// RunAtLoad starts the job when it is loaded (at boot for files in
	// DaemonDir).
	RunAtLoad bool
	// KeepAliveOnFailure restarts the job when it exits with an error or
	// crashes, but not after a clean exit.
	KeepAliveOnFailure bool
	// ThrottleInterval is the minimum number of seconds between starts
	// (0 keeps launchd's default of 10).
	ThrottleInterval int
	// WorkingDirectory, StdoutPath and StderrPath are optional absolute
	// paths.
	WorkingDirectory string
	StdoutPath       string
	StderrPath       string
	// Umask is applied to files the job creates; 0 keeps launchd's default.
	Umask int
	// Env is the job's whole environment besides what launchd adds.
	Env map[string]string
	// ExitTimeOut is how many seconds launchd waits after SIGTERM before
	// SIGKILL (0 keeps the default of 20).
	ExitTimeOut int
	// Agent writes a per-user launch agent for the graphical session
	// (ADR-0194): no UserName or GroupName (the agent runs as the user who
	// logs in), ProcessType Interactive and LimitLoadToSessionType Aqua,
	// so it starts only in a desktop session, never over ssh.
	Agent bool
}

// AgentDir is where launch agents for every user live; a user's own
// agents are in ~/Library/LaunchAgents.
const AgentDir = "/Library/LaunchAgents"

// ValidLabel accepts reverse-DNS labels of letters, digits, dots and
// dashes.
func ValidLabel(l string) bool {
	if l == "" || len(l) > 128 || strings.HasPrefix(l, ".") || strings.HasSuffix(l, ".") || strings.Contains(l, "..") {
		return false
	}
	for _, c := range l {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// validAbs accepts clean absolute paths without control characters.
func validAbs(p string) bool {
	if p == "" || len(p) > 1024 || p[0] != '/' || path.Clean(p) != p {
		return false
	}
	return !strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func (j Job) validate() error {
	if !ValidLabel(j.Label) {
		return fmt.Errorf("launchd etiketi geçersiz: %q", j.Label)
	}
	if len(j.Program) == 0 || !validAbs(j.Program[0]) {
		return errors.New("launchd programı mutlak bir yol olmalı")
	}
	for _, a := range j.Program[1:] {
		if len(a) > 4096 || strings.ContainsFunc(a, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return errors.New("launchd program argümanı geçersiz")
		}
	}
	for _, p := range []string{j.WorkingDirectory, j.StdoutPath, j.StderrPath} {
		if p != "" && !validAbs(p) {
			return fmt.Errorf("launchd yolu geçersiz: %q", p)
		}
	}
	if strings.Contains(j.Marker, "--") || strings.ContainsAny(j.Marker, "\r\n") {
		return errors.New("launchd işaret yorumu geçersiz")
	}
	if j.Umask < 0 || j.Umask > 0o777 || j.ThrottleInterval < 0 || j.ExitTimeOut < 0 {
		return errors.New("launchd sayısal alanı geçersiz")
	}
	for k, v := range j.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsFunc(k+v, func(r rune) bool { return r < 0x20 }) {
			return errors.New("launchd ortam değişkeni geçersiz")
		}
	}
	return nil
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// Plist returns the property list of j.
func Plist(j Job) ([]byte, error) {
	if err := j.validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	key := func(k string) { w("\t<key>" + esc(k) + "</key>") }
	str := func(k, v string) {
		key(k)
		w("\t<string>" + esc(v) + "</string>")
	}
	integer := func(k string, v int) {
		key(k)
		w("\t<integer>" + strconv.Itoa(v) + "</integer>")
	}
	w(`<?xml version="1.0" encoding="UTF-8"?>`)
	w(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`)
	if j.Marker != "" {
		w("<!-- " + esc(j.Marker) + " -->")
	}
	w(`<plist version="1.0">`)
	w("<dict>")
	str("Label", j.Label)
	key("ProgramArguments")
	w("\t<array>")
	for _, a := range j.Program {
		w("\t\t<string>" + esc(a) + "</string>")
	}
	w("\t</array>")
	key("RunAtLoad")
	if j.RunAtLoad {
		w("\t<true/>")
	} else {
		w("\t<false/>")
	}
	if j.KeepAliveOnFailure {
		key("KeepAlive")
		w("\t<dict>")
		w("\t\t<key>SuccessfulExit</key>")
		w("\t\t<false/>")
		w("\t</dict>")
	}
	if j.ThrottleInterval > 0 {
		integer("ThrottleInterval", j.ThrottleInterval)
	}
	if j.ExitTimeOut > 0 {
		integer("ExitTimeOut", j.ExitTimeOut)
	}
	if j.Umask > 0 {
		integer("Umask", j.Umask)
	}
	if j.Agent {
		str("ProcessType", "Interactive")
		str("LimitLoadToSessionType", "Aqua")
	} else {
		str("UserName", "root")
		str("GroupName", "wheel")
		str("ProcessType", "Standard")
	}
	if j.WorkingDirectory != "" {
		str("WorkingDirectory", j.WorkingDirectory)
	}
	if j.StdoutPath != "" {
		str("StandardOutPath", j.StdoutPath)
	}
	if j.StderrPath != "" {
		str("StandardErrorPath", j.StderrPath)
	}
	if len(j.Env) > 0 {
		key("EnvironmentVariables")
		w("\t<dict>")
		keys := make([]string, 0, len(j.Env))
		for k := range j.Env {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			w("\t\t<key>" + esc(k) + "</key>")
			w("\t\t<string>" + esc(j.Env[k]) + "</string>")
		}
		w("\t</dict>")
	}
	w("</dict>")
	w("</plist>")
	return []byte(b.String()), nil
}

// HasMarker reports whether a property list carries marker as the XML
// comment Plist writes.
func HasMarker(data []byte, marker string) bool {
	if marker == "" {
		return false
	}
	head := data
	if len(head) > 1024 {
		head = head[:1024]
	}
	return strings.Contains(string(head), "<!-- "+esc(marker)+" -->")
}

// Path is the file of a launch daemon label in DaemonDir.
func Path(label string) string { return DaemonDir + "/" + label + ".plist" }

// Target is launchctl's name of a system daemon, e.g. system/com.openscale.device.
func Target(label string) string { return "system/" + label }

// PrintState is the part of `launchctl print system/<label>` the callers
// need.
type PrintState struct {
	State string
	PID   int
	Path  string
}

// ParsePrint reads the top-level "state", "pid" and "path" lines of
// `launchctl print`. The output format is not a stable interface; unknown
// lines are ignored.
func ParsePrint(out []byte) PrintState {
	var st PrintState
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "state":
			if st.State == "" {
				st.State = v
			}
		case "pid":
			if st.PID == 0 {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					st.PID = n
				}
			}
		case "path":
			if st.Path == "" {
				st.Path = v
			}
		}
	}
	return st
}

// Disabled reports whether `launchctl print-disabled system` lists label
// as disabled ("=> disabled" on current systems, "=> true" on older ones).
func Disabled(out []byte, label string) bool {
	quoted := `"` + label + `"`
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if !ok || strings.TrimSpace(k) != quoted {
			continue
		}
		v = strings.TrimSpace(v)
		return v == "disabled" || v == "true"
	}
	return false
}
