package tpm

import (
	"bytes"
	"errors"
	"testing"
)

func TestDeviceKeySealWiring(t *testing.T) {
	old := DeviceKeySealer
	t.Cleanup(func() { DeviceKeySealer = old })
	sim := newSim(0x21)
	DeviceKeySealer = func() (Sealer, error) { return NewTPM2Sealer(sim), nil }

	plain := []byte(`{"format":"x"}`)
	if got, sealed, err := UnwrapDeviceKey(plain); err != nil || sealed || !bytes.Equal(got, plain) {
		t.Fatalf("plain key: %v %v", sealed, err)
	}
	env, err := SealDeviceKey(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, kind := SealedKind(env); !ok || kind != "tpm2" {
		t.Fatalf("kind %v %q", ok, kind)
	}
	if ok, _ := SealedKind(plain); ok {
		t.Fatal("plain reported sealed")
	}
	got, sealed, err := UnwrapDeviceKey(env)
	if err != nil || !sealed || !bytes.Equal(got, plain) {
		t.Fatalf("unwrap: %v %v", sealed, err)
	}
	if _, err := SealDeviceKey(env, nil); err == nil {
		t.Fatal("sealed twice")
	}
	// Another computer (other TPM) cannot open it.
	DeviceKeySealer = func() (Sealer, error) { return NewTPM2Sealer(newSim(0x22)), nil }
	if _, _, err := UnwrapDeviceKey(env); err == nil {
		t.Fatal("foreign TPM opened the key")
	}
	DeviceKeySealer = func() (Sealer, error) { return nil, ErrUnsupported }
	if _, sealed, err := UnwrapDeviceKey(env); err == nil || !sealed || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("no sealer: %v", err)
	}
}
