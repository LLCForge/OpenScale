// Package web embeds the statically exported Next.js panel. The dist
// directory is filled by `pnpm --dir panel build`; when it holds only
// .gitkeep, the server shows a page explaining how to build the panel.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the exported panel files rooted at dist.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// fs.Sub only fails for an invalid path, which "dist" is not.
		panic(err)
	}
	return sub
}
