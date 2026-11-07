// Package healthmon watches the owner's own network (ADR-0216): whether
// home services answer (HTTP and TCP probes, #781), whether watched
// devices are online (#782), which devices joined or left the signed
// document (#783), disk space and battery health (#774), per-device link
// quality history (#764) and the speed test button (#763).
//
// Probes reach only tunnel addresses and prefixes the owner listed; the
// package never contacts anything else (ADR-0008). Every watcher produces
// Events that the caller turns into notifications with Event.Message.
package healthmon

import (
	"time"

	"github.com/openscale/openscale/internal/notify"
)

// Event kinds.
const (
	KindServiceDown   = "service_down"
	KindServiceUp     = "service_up"
	KindDeviceOffline = "device_offline"
	KindDeviceOnline  = "device_online"
	KindDeviceJoined  = "device_joined"
	KindDeviceLeft    = "device_left"
	KindDeviceRenamed = "device_renamed"
	KindDiskLow       = "disk_low"
	KindDiskOK        = "disk_ok"
	KindBatteryWorn   = "battery_worn"
	KindBatteryLow    = "battery_low"
)

// Severity of an event.
type Severity string

// Severities.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Event is one state change worth telling the owner about. It carries
// names and numbers, never addresses.
type Event struct {
	Kind     string    `json:"kind"`
	Severity Severity  `json:"severity"`
	Subject  string    `json:"subject"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
	At       time.Time `json:"at"`
}

// Message converts the event into a notification.
func (e Event) Message() notify.Message {
	p := notify.PriorityNormal
	switch e.Severity {
	case SeverityInfo:
		p = notify.PriorityLow
	case SeverityCritical:
		p = notify.PriorityHigh
	}
	return notify.Message{Kind: e.Kind, Subject: e.Subject, Title: e.Title, Body: e.Detail, Priority: p, At: e.At}
}
