package peercred

import "strconv"

// HasGroup reports whether the numeric group id gid is among id.Groups
// (Linux and macOS fill Groups with numeric ids).
func (id Identity) HasGroup(gid int) bool {
	want := strconv.Itoa(gid)
	for _, g := range id.Groups {
		if g == want {
			return true
		}
	}
	return false
}
