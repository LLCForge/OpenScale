//go:build !windows && !linux && !darwin

package privacy

func processNames() ([]string, error) { return nil, ErrScreenShareUnsupported }
