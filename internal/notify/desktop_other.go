//go:build !linux && !darwin

package notify

func localCommand(Message) (string, []string, bool) { return "", nil, false }
