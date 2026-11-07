//go:build !windows

package osnet

import "errors"

// WFPRisk is one configuration that could let traffic past the kill
// switch (#499); Windows only.
type WFPRisk struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// errWFPAuditUnsupported: there is no Windows Filtering Platform here.
var errWFPAuditUnsupported = errors.New("WFP denetimi yalnızca Windows'ta")

// KillSwitchBypassRisks is Windows only.
func KillSwitchBypassRisks() ([]WFPRisk, error) { return nil, errWFPAuditUnsupported }
