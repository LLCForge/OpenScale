package srvaudit

import (
	"io/fs"
	"path"
	"strings"
)

// sshdConfig is the global section of sshd_config with its includes. As in
// sshd, the first value of a keyword wins; Match blocks are not evaluated
// (the rest of a file after a Match line is skipped).
type sshdConfig struct {
	values map[string]string
}

const (
	maxIncludeDepth = 4
	maxSSHDFiles    = 64
)

// readSSHD returns nil when sshd is not configured on the system.
func readSSHD(fsys fs.FS) *sshdConfig {
	data, err := readSmall(fsys, "etc/ssh/sshd_config")
	if err != nil {
		return nil
	}
	c := &sshdConfig{values: map[string]string{}}
	files := 0
	c.parse(fsys, data, 0, &files)
	return c
}

func (c *sshdConfig) get(key, def string) string {
	if v, ok := c.values[key]; ok {
		return v
	}
	return def
}

// parse reads one file's text.
func (c *sshdConfig) parse(fsys fs.FS, text string, depth int, files *int) {
	*files++
	for _, line := range strings.Split(text, "\n") {
		key, val := splitSSHDLine(line)
		if key == "" {
			continue
		}
		switch key {
		case "match":
			return
		case "include":
			if depth >= maxIncludeDepth {
				continue
			}
			for _, pattern := range strings.Fields(val) {
				c.include(fsys, pattern, depth, files)
			}
			continue
		}
		if _, set := c.values[key]; !set {
			c.values[key] = val
		}
	}
}

func (c *sshdConfig) include(fsys fs.FS, pattern string, depth int, files *int) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/etc/ssh/" + pattern
	}
	pattern = strings.TrimPrefix(path.Clean(pattern), "/")
	if pattern == "" || strings.HasPrefix(pattern, "..") {
		return
	}
	matches, err := fs.Glob(fsys, pattern)
	if err != nil {
		return
	}
	for _, m := range matches { // fs.Glob returns lexical order, like sshd
		if *files >= maxSSHDFiles {
			return
		}
		data, err := readSmall(fsys, m)
		if err != nil {
			continue
		}
		c.parse(fsys, data, depth+1, files)
	}
}

// splitSSHDLine returns the lowercased keyword and its value; comments and
// blank lines give an empty keyword. Keyword and value are separated by
// spaces, tabs or one '='.
func splitSSHDLine(line string) (string, string) {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if line == "" || line[0] == '#' {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key := strings.ToLower(line[:i])
	rest := strings.TrimSpace(line[i:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	rest = strings.Trim(rest, `"`)
	return key, rest
}
