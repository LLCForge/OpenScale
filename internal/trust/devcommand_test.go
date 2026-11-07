package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeviceCommandRoundTrip(t *testing.T) {
	f := newFixture(t)
	deviceID := strings.Repeat("ab", 16)
	cmd, err := NewDeviceCommand(f.doc.NetworkID, deviceID, CommandWipe, 0, testNow, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignDeviceCommand(f.rootPriv, cmd)
	if err != nil {
		t.Fatal(err)
	}
	line, err := EncodeDeviceCommand(env)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDeviceCommand(line)
	if err != nil {
		t.Fatal(err)
	}
	st := &State{Anchor: f.anchor}
	got, err := OpenDeviceCommand(decoded, st, deviceID, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("OpenDeviceCommand: %v", err)
	}
	if got.Action != CommandWipe || got.Nonce != cmd.Nonce {
		t.Fatalf("got %+v", got)
	}
	var log CommandLog
	if err := log.Use(got, testNow); err != nil {
		t.Fatal(err)
	}
	if err := log.Use(got, testNow); !errors.Is(err, ErrCommandReplayed) {
		t.Fatalf("replay: %v", err)
	}
	// Hardware-signed commands verify too (ADR-0123).
	hw, err := SignDeviceCommandWith(pureSigner{f.rootPriv}, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDeviceCommand(hw, st, deviceID, testNow); err != nil {
		t.Fatalf("digest-signed command: %v", err)
	}
}

func TestDeviceCommandRejections(t *testing.T) {
	f := newFixture(t)
	deviceID := strings.Repeat("ab", 16)
	cmd, err := NewDeviceCommand(f.doc.NetworkID, deviceID, CommandLock, 0, testNow, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignDeviceCommand(f.rootPriv, cmd)
	if err != nil {
		t.Fatal(err)
	}
	st := &State{Anchor: f.anchor}
	if _, err := OpenDeviceCommand(env, st, strings.Repeat("cd", 16), testNow); !errors.Is(err, ErrCommandTarget) {
		t.Errorf("other device: %v", err)
	}
	if _, err := OpenDeviceCommand(env, st, deviceID, testNow.Add(2*time.Hour)); !errors.Is(err, ErrCommandExpired) {
		t.Errorf("expired: %v", err)
	}
	if _, err := OpenDeviceCommand(env, st, deviceID, testNow.Add(-time.Hour)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("future: %v", err)
	}
	rotated := &State{Anchor: f.anchor, Epoch: 1}
	if _, err := OpenDeviceCommand(env, rotated, deviceID, testNow); !errors.Is(err, ErrEpochMismatch) {
		t.Errorf("old epoch: %v", err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := SignDeviceCommand(otherPriv, cmd)
	if _, err := OpenDeviceCommand(forged, st, deviceID, testNow); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged: %v", err)
	}
	// A root-signed document is not a command.
	docEnv := f.sign(t, f.doc)
	if _, err := OpenDeviceCommand(docEnv, st, deviceID, testNow); !errors.Is(err, ErrWrongContext) {
		t.Errorf("document as command: %v", err)
	}
	if _, err := NewDeviceCommand(f.doc.NetworkID, deviceID, "reboot", 0, testNow, time.Hour, rand.Reader); err == nil {
		t.Error("unknown action accepted")
	}
	if _, err := NewDeviceCommand(f.doc.NetworkID, deviceID, CommandLock, 0, testNow, 8*24*time.Hour, rand.Reader); err == nil {
		t.Error("long validity accepted")
	}
	if _, err := DecodeDeviceCommand("oscmd1.!!"); err == nil {
		t.Error("garbage decoded")
	}
}

func TestCommandLogFailsClosedWhenFull(t *testing.T) {
	var log CommandLog
	for i := range MaxCommandLog {
		c := &DeviceCommand{Nonce: strings.Repeat("0", 28) + string(rune('a'+i%6)) + string(rune('a'+(i/6)%6)) + string(rune('a'+(i/36)%6)) + string(rune('a'+(i/216)%6)), ExpiresAt: testNow.Add(time.Hour)}
		if err := log.Use(c, testNow); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	c := &DeviceCommand{Nonce: strings.Repeat("1", 32), ExpiresAt: testNow.Add(time.Hour)}
	if err := log.Use(c, testNow); err == nil {
		t.Fatal("full log accepted a new command")
	}
	// Once entries expire there is room again.
	if err := log.Use(c, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func FuzzDecodeDeviceCommand(f *testing.F) {
	fx := newFixtureF(f)
	deviceID := strings.Repeat("ab", 16)
	cmd, _ := NewDeviceCommand(fx.doc.NetworkID, deviceID, CommandLock, 0, testNow, time.Hour, rand.Reader)
	env, _ := SignDeviceCommand(fx.rootPriv, cmd)
	line, _ := EncodeDeviceCommand(env)
	f.Add(line)
	f.Add("oscmd1.e30")
	f.Fuzz(func(t *testing.T, line string) {
		env, err := DecodeDeviceCommand(line)
		if err != nil {
			return
		}
		st := &State{Anchor: fx.anchor}
		c, err := OpenDeviceCommand(env, st, deviceID, testNow)
		if err != nil {
			return
		}
		if c.DeviceID != deviceID || c.NetworkID != fx.doc.NetworkID {
			t.Fatal("accepted a command for another target")
		}
	})
}
