//go:build !windows

package securefile

// checkDirOwner is Windows only: elsewhere 0700 directories and the
// permission checks of ReadPrivate do this job.
func checkDirOwner(string) error { return nil }
