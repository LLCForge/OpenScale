//go:build !windows

package winapp

// FirewallRulesPresent is Windows only.
func FirewallRulesPresent() (bool, error) { return false, ErrUnsupported }
