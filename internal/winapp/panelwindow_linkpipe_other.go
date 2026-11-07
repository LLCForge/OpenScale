//go:build !windows

package winapp

// ReadPanelLinkPipe is Windows only: only the elevated Windows tray starts
// the window process with another token.
func ReadPanelLinkPipe(string) (string, error) { return "", ErrUnsupported }
