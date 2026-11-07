// Package policy holds repository-wide checks that enforce architecture
// decisions, such as the dependency allowlist from ADR-0002.
package policy

// AllowedModulePrefixes lists the only Go modules OpenScale may depend on
// (ADR-0002). Adding a prefix requires a new ADR.
var AllowedModulePrefixes = []string{
	"github.com/openscale/openscale",
	"golang.org/x/",
	"golang.zx2c4.com/wireguard",
	"golang.zx2c4.com/wintun",
	// ADR-0217: sahip onaylı tek istisna (WASM eklenti çalıştırıcısı).
	"github.com/tetratelabs/wazero",
}
