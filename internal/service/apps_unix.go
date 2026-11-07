//go:build !windows

package service

import "os/user"

// sshRuleUser maps the account a client asks for to the name rules use.
// POSIX account names are case sensitive and rules list them exactly.
func sshRuleUser(user string) (string, bool) { return user, user != "" }

// accountIsSuperuser reports whether the local account has uid 0, so a
// second name for root still needs allow_root.
func accountIsSuperuser(name string) bool {
	u, err := user.Lookup(name)
	return err == nil && u.Uid == "0"
}
