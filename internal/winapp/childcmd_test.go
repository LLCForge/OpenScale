package winapp

import "os/exec"

func newChildCommand(exe string, args ...string) *exec.Cmd { return exec.Command(exe, args...) }
