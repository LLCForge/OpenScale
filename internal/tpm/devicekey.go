package tpm

import (
	"errors"
	"io"
)

// Device key sealing (#602, ADR-0208): device.key may hold either the
// usual (DPAPI or owner-only) key file or an envelope from SealEnvelope.
// The service and the CLI read both through UnwrapDeviceKey, so a sealed
// key works everywhere the plain one did.

// DeviceKeySealer returns the sealer used for device keys. It is a
// variable so tests can use a fake; the default is the machine sealer.
var DeviceKeySealer = func() (Sealer, error) { return PlatformSealer(true) }

// UnwrapDeviceKey returns data itself (sealed=false) when it is not an
// envelope, or the opened plain key (sealed=true). The caller wipes the
// returned slice when sealed is true.
func UnwrapDeviceKey(data []byte) (plain []byte, sealed bool, err error) {
	if !IsEnvelope(data) {
		return data, false, nil
	}
	s, err := DeviceKeySealer()
	if err != nil {
		return nil, true, errors.Join(errors.New("cihaz anahtarı TPM ile mühürlü ama bu bilgisayarda mühür açılamıyor"), err)
	}
	p, err := OpenEnvelope(s, data)
	if err != nil {
		return nil, true, errors.Join(errors.New("mühürlü cihaz anahtarı açılamadı"), err)
	}
	return p, true, nil
}

// SealedKind reports whether data is an envelope and which mechanism
// sealed it ("tpm2", "ncrypt" or "" when unknown).
func SealedKind(data []byte) (bool, string) {
	k, _, _, _, _, err := ParseEnvelope(data)
	if err != nil {
		return false, ""
	}
	switch k {
	case kindTPM2:
		return true, "tpm2"
	case kindNCrypt:
		return true, "ncrypt"
	}
	return true, ""
}

// SealDeviceKey seals plain with the device key sealer. The envelope is
// returned only after it was opened again successfully (SealEnvelope).
func SealDeviceKey(plain []byte, random io.Reader) ([]byte, error) {
	if IsEnvelope(plain) {
		return nil, errors.New("cihaz anahtarı zaten mühürlü")
	}
	s, err := DeviceKeySealer()
	if err != nil {
		return nil, err
	}
	return SealEnvelope(s, plain, random)
}
