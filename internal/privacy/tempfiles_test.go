package privacy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoSystemTempFiles is the #46 rule: shipped code never creates files
// in the system temporary directory (shared, often world-readable, kept
// after a crash). Temporary files go next to their target inside the
// owner-only data directory (securefile.Replace) and stale ones are
// removed at start (securefile.RemoveStaleTemps).
func TestNoSystemTempFiles(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "os" {
					return true
				}
				pos := fset.Position(call.Pos())
				switch sel.Sel.Name {
				case "TempDir":
					t.Errorf("%s: os.TempDir in shipped code", pos)
				case "CreateTemp", "MkdirTemp":
					if len(call.Args) > 0 {
						if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == `""` {
							t.Errorf("%s: os.%s in the system temporary directory", pos, sel.Sel.Name)
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
