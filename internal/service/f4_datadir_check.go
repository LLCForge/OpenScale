package service

import (
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/winapp"
)

// serviceDataDir is the folder the Windows installer locks; a seam for tests.
var serviceDataDir = winapp.DataDir

// checkWindowsDataDir reports a service data folder that is open to, or holds
// objects of, other accounts: the ACL is the only protection of key files
// sealed with the machine's DPAPI scope. A foreground state folder lives in
// the user's own profile and is not judged. It only reads.
func (c *checker) checkWindowsDataDir(dir string) {
	want := serviceDataDir()
	if want == "" || !strings.EqualFold(filepath.Clean(dir), filepath.Clean(want)) {
		return
	}
	if err := winapp.DataDirProblem(dir); err != nil {
		c.add(FindingWarn, "veri klasörü", "%v; 'openscale service install' izinleri yeniden denetler", err)
	}
}
