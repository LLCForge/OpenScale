//go:build linux

package sysinfo

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Samba shares (ADR-0226): the configuration as Samba itself reads it
// ("testparm -s", includes resolved) or, without testparm, smb.conf as
// written; then the user-defined shares ("net usershare list -l"). The
// programs are looked up only in the system's own folders, never through
// PATH, and run without a shell.

const shareCmdTimeout = 5 * time.Second

// shareBinDirs are the only folders the Samba tools are taken from.
var shareBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}

// smbConfPath is Samba's default configuration file.
const smbConfPath = "/etc/samba/smb.conf"

func listShares() []Share {
	var out []Share
	if data, ok := runShareTool("testparm", "-s", "--suppress-prompt"); ok {
		out = ParseSambaConfig(bytes.NewReader(data))
	} else if f, err := os.Open(smbConfPath); err == nil {
		out = ParseSambaConfig(f)
		_ = f.Close()
	}
	if data, ok := runShareTool("net", "usershare", "list", "-l"); ok {
		out = append(out, ParseUsershareList(bytes.NewReader(data))...)
	}
	return out
}

// runShareTool runs a Samba tool from a system folder and returns its
// standard output; ok is false when the tool is missing or fails.
func runShareTool(name string, args ...string) ([]byte, bool) {
	path := ""
	for _, dir := range shareBinDirs {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			path = p
			break
		}
	}
	if path == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), shareCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/usr/sbin:/bin:/sbin"}
	var stdout bytes.Buffer
	cmd.Stdout = &limitedBuffer{buf: &stdout, max: maxSambaConf}
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return stdout.Bytes(), true
}

// limitedBuffer keeps at most max bytes and discards the rest.
type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) <= room {
			l.buf.Write(p)
		} else {
			l.buf.Write(p[:room])
		}
	}
	return len(p), nil
}
