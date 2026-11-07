package openscale

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// ExitNodes lists the names of the exit nodes in the joined network
// document as a JSON array, sorted, without expired members. The TV
// interface (#476) and the home screen widget (#472) offer them as
// buttons because typing a name with a remote control is impractical.
// The tunnel still checks the chosen name against the document (Plan).
func ExitNodes(stateDir string) (string, error) {
	if err := checkStateDir(stateDir); err != nil {
		return "", err
	}
	store, err := member.Open(stateDir)
	if err != nil {
		return "", err
	}
	doc := store.Document()
	now := time.Now()
	names := []string{}
	for _, d := range doc.Devices {
		if d.HasRole(trust.RoleExitNode) && d.ExpiresAt.After(now) {
			names = append(names, d.Name)
		}
	}
	slices.Sort(names)
	out, err := json.Marshal(slices.Compact(names))
	if err != nil {
		return "", err
	}
	return string(out), nil
}
