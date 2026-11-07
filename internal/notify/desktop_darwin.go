//go:build darwin

package notify

func localCommand(m Message) (string, []string, bool) {
	return "osascript", osascriptArgs(m), true
}
