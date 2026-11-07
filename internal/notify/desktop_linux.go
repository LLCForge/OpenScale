//go:build linux

package notify

func localCommand(m Message) (string, []string, bool) {
	return "notify-send", notifySendArgs(m), true
}
