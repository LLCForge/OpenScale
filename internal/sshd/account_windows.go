//go:build windows

package sshd

import (
	"errors"
	"fmt"
	"os/user"
	"strings"
)

// account is the local account a session runs as.
type account struct {
	name string
	home string
}

// resolveAccount accepts only the account the server itself runs as.
// Switching to another Windows account needs that account's credentials
// (LogonUser) or S4U logon, which this server deliberately does not do.
// When the service runs as LocalSystem the account name is "SYSTEM".
func resolveAccount(name string) (*account, error) {
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("hizmet kullanıcısı okunamadı: %w", err)
	}
	short := u.Username
	if i := strings.LastIndexByte(short, byte(0x5C)); i >= 0 { // backslash
		short = short[i+1:]
	}
	if !strings.EqualFold(name, short) {
		return nil, errors.New("Windows'ta yalnızca hizmetin kendi kullanıcısıyla oturum açılabilir")
	}
	return &account{name: short, home: u.HomeDir}, nil
}
