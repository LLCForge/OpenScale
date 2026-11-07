//go:build darwin

package updater

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// PlatformSignature checks the file's code signature with
// /usr/bin/codesign (strict, offline). An unsigned file is
// SignatureAbsent; any other failure is SignatureInvalid.
func PlatformSignature(path string) (SignatureState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var out bytes.Buffer
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return SignatureValid, nil
	}
	msg := strings.TrimSpace(out.String())
	if strings.Contains(msg, "not signed at all") {
		return SignatureAbsent, nil
	}
	if _, ok := err.(*exec.ExitError); !ok {
		// codesign itself missing (no developer tools): not checked.
		return SignatureUnknown, err
	}
	return SignatureInvalid, fmt.Errorf("codesign: %s", msg)
}
