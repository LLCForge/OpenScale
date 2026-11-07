//go:build unix

package sshd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// account is the local account a session runs as.
type account struct {
	name       string
	home       string
	uid, gid   uint32
	groups     []uint32
	switchUser bool
}

// resolveAccount maps a login name to a local account. When the server
// runs as root, sessions switch to that account (including root itself
// only if Authorize allowed it). Otherwise only the server's own account
// can be used, because switching users needs privileges.
func resolveAccount(name string) (*account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("yerel kullanıcı bulunamadı: %w", err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, errors.New("geçersiz kullanıcı kimliği")
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, errors.New("geçersiz grup kimliği")
	}
	a := &account{name: u.Username, home: u.HomeDir, uid: uint32(uid), gid: uint32(gid)}
	euid := os.Geteuid()
	switch {
	case euid == 0:
		a.switchUser = true
		ids, err := u.GroupIds()
		if err != nil {
			return nil, fmt.Errorf("kullanıcı grupları okunamadı: %w", err)
		}
		for _, g := range ids {
			v, err := strconv.ParseUint(g, 10, 32)
			if err != nil {
				continue
			}
			a.groups = append(a.groups, uint32(v))
		}
	case uint64(euid) != uid:
		return nil, errors.New("hizmet yalnızca kendi kullanıcısı olarak oturum açtırabilir")
	}
	return a, nil
}
