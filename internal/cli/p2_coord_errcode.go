package cli

import (
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/errcode"
)

// The coordinator's refusal audit records stable error codes (#187).
func init() { coordinator.ErrorCode = errcode.Classify }
