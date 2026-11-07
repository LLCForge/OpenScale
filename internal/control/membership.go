package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Membership extensions (ADR-0027, ADR-0028). Like the ADR-0025 extensions
// they are separate message types carrying only existing fields, used only
// after the coordinator announced them in a caps reply; an old coordinator
// answers "unknown message type" and an old device never sends them.
const (
	// TypeRoot pages through the coordinator's root transitions. Request:
	// Offset (index). Reply: Version is the coordinator's root epoch, Total
	// the number of transitions, Data and Sig the transition at Offset.
	TypeRoot = "root"
	// TypeRootPut hands the coordinator a root transition (Data, Sig). It
	// keeps it only if it applies to its own state (member.Store).
	TypeRootPut = "rput"
	// TypeLeave carries this device's signed leave request (Data, Sig).
	TypeLeave = "leave"
	// TypeLeaves pages through leave requests (admin devices only); Target
	// is the device id of the request in Data and Sig.
	TypeLeaves = "leaves"
	// TypeReject drops a pending invite enrollment (admin devices only):
	// Target is the invite id, Data the device id.
	TypeReject = "reject"
	// TypeAlerts pages through clone alerts (admin devices only); Data is
	// one JSON-encoded CloneAlert.
	TypeAlerts = "alerts"
	// TypeClientVersion reports this device's OpenScale version in Data.
	TypeClientVersion = "ver"
)

// Feature names of the membership extensions.
const (
	FeatureRoot    = "root"
	FeatureLeave   = "leave"
	FeatureReject  = "reject"
	FeatureAlerts  = "alerts"
	FeatureVersion = "ver"
)

// MaxClientVersionLen bounds the reported version string.
const MaxClientVersionLen = 64

// ErrVersionNotReported is the start of the coordinator's error when a
// device of a network with a minimum client version did not report its
// version yet; the device reports it and asks again.
const ErrVersionNotReported = "istemci sürümü bildirilmedi"

// CloneAlert tells the owner that one device identity was seen at two
// endpoints at once (F-137): the same key was most likely copied to a
// second computer.
type CloneAlert struct {
	DeviceID  string    `json:"device"`
	Name      string    `json:"name"`
	Flips     int       `json:"flips"`
	Endpoints []string  `json:"endpoints"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
}

// maxAlertEndpoints bounds the endpoints carried by one alert.
const maxAlertEndpoints = 2

// EncodeCloneAlert encodes an alert for a TypeAlerts reply.
func EncodeCloneAlert(a CloneAlert) ([]byte, error) {
	if len(a.Endpoints) > maxAlertEndpoints {
		a.Endpoints = a.Endpoints[:maxAlertEndpoints]
	}
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if len(data) > ChunkSize {
		return nil, errors.New("clone alert too large")
	}
	return data, nil
}

// DecodeCloneAlert strictly decodes an alert received from the coordinator.
func DecodeCloneAlert(data []byte) (CloneAlert, error) {
	var a CloneAlert
	if len(data) == 0 || len(data) > ChunkSize {
		return a, errors.New("clone alert has an invalid size")
	}
	if err := decodeStrictJSON(data, &a); err != nil {
		return a, err
	}
	if len(a.DeviceID) != 32 || len(a.Name) > maxNameLen || a.Flips < 0 || len(a.Endpoints) > maxAlertEndpoints {
		return a, errors.New("clone alert out of range")
	}
	for _, e := range a.Endpoints {
		if len(e) > MaxCandidateLen {
			return a, errors.New("clone alert out of range")
		}
	}
	return a, nil
}

func decodeStrictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
