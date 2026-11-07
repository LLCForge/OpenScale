//go:build !windows

package osnet

// NRPTGroupPolicyWarning is empty off Windows: there is no NRPT (#272).
func NRPTGroupPolicyWarning(DNSConfig) string { return "" }
