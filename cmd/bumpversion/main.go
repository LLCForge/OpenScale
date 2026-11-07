// Command bumpversion computes the next OpenScale version by the scheme of
// ADR-0193 (MINOR 0-9, x.9 -> (x+1).0, PATCH, beta.N). It prints the new
// version; with -w it also writes it to the VERSION file.
//
//	go run ./cmd/bumpversion [-file VERSION] [-w] minor|patch|beta|release
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("bumpversion", flag.ContinueOnError)
	file := fs.String("file", "VERSION", "sürüm dosyası")
	write := fs.Bool("w", false, "yeni sürümü dosyaya yaz")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "kullanım: bumpversion [-file VERSION] [-w] minor|patch|beta|release")
		return 2
	}
	path := filepath.Clean(*file)
	info, err := os.Lstat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hata: %v\n", err)
		return 1
	}
	if !info.Mode().IsRegular() || info.Size() > 256 {
		fmt.Fprintln(os.Stderr, "hata: sürüm dosyası düzenli ve küçük bir dosya olmalı")
		return 1
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hata: %v\n", err)
		return 1
	}
	next, err := version.Bump(strings.TrimSpace(string(cur)), fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "hata: %v\n", err)
		return 1
	}
	if *write {
		if err := os.WriteFile(path, []byte(next+"\n"), info.Mode().Perm()); err != nil {
			fmt.Fprintf(os.Stderr, "hata: %v\n", err)
			return 1
		}
	}
	fmt.Println(next)
	return 0
}
