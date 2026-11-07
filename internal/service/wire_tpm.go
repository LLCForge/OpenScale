package service

import (
	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

// unmarshalDeviceKey reads a device key that is either plain or sealed to
// this computer's TPM (#602, ADR-0208). The opened copy is wiped.
func unmarshalDeviceKey(data []byte) (*trust.DeviceSecrets, error) {
	plain, sealed, err := tpm.UnwrapDeviceKey(data)
	if err != nil {
		return nil, err
	}
	if sealed {
		defer clear(plain)
	}
	return trust.UnmarshalDeviceSecrets(plain)
}
