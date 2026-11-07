//go:build linux

package tpm

// PlatformSealer returns raw TPM 2.0 sealing over /dev/tpmrm0. machine is
// ignored (the resource manager device is the only scope). The caller
// closes it with Close.
func PlatformSealer(bool) (Sealer, error) {
	t, err := Open()
	if err != nil {
		return nil, err
	}
	return NewTPM2Sealer(t), nil
}
