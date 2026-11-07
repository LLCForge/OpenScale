package peercred

// WindowProcess returns the OpenScale window process pid belongs to (pid
// itself or its nearest ancestor running an allowed program), 0 when there
// is none. It records nothing.
func (b *WindowBinding) WindowProcess(pid int) int {
	return b.windowOf(pid)
}
