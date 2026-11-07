package sftpclient

import (
	"path"
	"strings"
)

// CleanAbs checks that p is an absolute remote path and returns it
// cleaned ("/a/b/../c" is "/a/c"). SFTP paths use "/" on every server;
// a Windows OpenSSH server shows drives as "/C:/...".
func CleanAbs(p string) (string, error) {
	if err := checkPath(p); err != nil || !strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return "", ErrBadPath
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", ErrBadPath
		}
	}
	return path.Clean(p), nil
}

// Join appends the single element name to the absolute directory dir.
// name must pass ValidName, so it cannot climb out of dir.
func Join(dir, name string) (string, error) {
	d, err := CleanAbs(dir)
	if err != nil || !ValidName(name) || strings.ContainsRune(name, '\\') {
		return "", ErrBadPath
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", ErrBadPath
		}
	}
	out := path.Join(d, name)
	if len(out) > MaxPath {
		return "", ErrBadPath
	}
	return out, nil
}
