package mqttpub

import (
	"encoding/json"
	"time"
)

// Status is the retained state message of a device. It never holds keys,
// endpoints or addresses.
type Status struct {
	Schema      int       `json:"schema"`
	Device      string    `json:"device"`
	At          time.Time `json:"at"`
	Running     bool      `json:"running"`
	Connected   bool      `json:"connected"`
	Peers       int       `json:"peers"`
	PeersOnline int       `json:"peers_online"`
	PeersRelay  int       `json:"peers_relay"`
	ExitNode    string    `json:"exit_node,omitempty"`
	Healthy     bool      `json:"healthy"`
}

// Event is one event of the local event stream (ADR-0105).
type Event struct {
	Schema   int       `json:"schema"`
	Device   string    `json:"device"`
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Category string    `json:"category"`
	Severity string    `json:"severity"`
	Peer     string    `json:"peer,omitempty"`
	Message  string    `json:"message"`
}

// maxMessage bounds one payload.
const maxMessage = 8 << 10

// Encode returns the JSON payload, cutting an overlong message text.
func (e Event) Encode() ([]byte, error) {
	if len(e.Message) > maxMessage/2 {
		e.Message = e.Message[:maxMessage/2]
	}
	e.Schema = 1
	return json.Marshal(e)
}

// Encode returns the JSON payload.
func (s Status) Encode() ([]byte, error) {
	s.Schema = 1
	return json.Marshal(s)
}
