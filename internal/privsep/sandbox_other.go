//go:build !linux && !windows

package privsep

func helperAccount() (uint32, uint32, error) { return 0, 0, nil }

func contain(int) (func(), error) { return func() {}, nil }

// confine is never reached: Enter refuses on this system.
func confine() string { return "" }
