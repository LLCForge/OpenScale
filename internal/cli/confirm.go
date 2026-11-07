package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// Explicit confirmation of security-critical changes (F-134, #231).
// Revoking a device and adding a rule that opens every device to every
// device cannot be confirmed with a generic --yes: the owner types the
// device name (or GENIS) at the prompt, or a script passes exactly that
// text with --confirm. A generic --yes stays for operations that do not
// weaken security (for example "privacy uninstall --purge").

// wideRuleWord confirms an allow rule from every device to every device.
const wideRuleWord = "GENIS"

// errNotConfirmed is returned when the typed text does not match.
var errNotConfirmed = errors.New("onaylanmadı; hiçbir şey değiştirilmedi")

// confirmCritical accepts the change when given (--confirm) equals want, or
// when the owner types want at the terminal.
func confirmCritical(env *Env, given, want, what string) error {
	if given != "" {
		if strings.TrimSpace(given) == want {
			return nil
		}
		return fmt.Errorf("%w: --confirm %q olmalı", errNotConfirmed, want)
	}
	if env.IsTerminal == nil || !env.IsTerminal() || env.ReadLine == nil {
		return usageError("%s açık onay ister; terminal yok, --confirm %s verin", what, want)
	}
	answer, err := env.ReadLine(fmt.Sprintf("%s. Onaylamak için %s yazın: ", what, want))
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != want {
		return errNotConfirmed
	}
	return nil
}

// wideRule reports an allow rule from every device to every device on
// every port.
func wideRule(r trust.Rule) bool {
	if r.Action == trust.RuleDeny || r.Service != "" {
		return false
	}
	return slices.Contains(r.From, "*") && slices.Contains(r.To, "*") &&
		(r.Protocol == "any" || len(r.Ports) == 0 || slices.Contains(r.Ports, "*") || slices.Contains(r.Ports, "1-65535"))
}
