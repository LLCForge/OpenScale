package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDependencyAllowlist fails if go.mod requires any module outside the
// ADR-0002 allowlist, including indirect dependencies.
func TestDependencyAllowlist(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	inRequire := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "require ("):
			inRequire = true
			continue
		case inRequire && line == ")":
			inRequire = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inRequire:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "//") {
			continue
		}
		if !allowed(fields[0]) {
			t.Errorf("module %s is not allowed by ADR-0002; add an ADR before depending on it", fields[0])
		}
	}
}

func allowed(module string) bool {
	for _, prefix := range AllowedModulePrefixes {
		if strings.HasPrefix(module, prefix) {
			return true
		}
	}
	return false
}
