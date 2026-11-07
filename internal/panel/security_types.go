package panel

import "time"

// LocalSecurity is this computer's exposure check.
type LocalSecurity struct {
	Supported bool            `json:"supported"`
	RDP       ServiceAccess   `json:"rdp"`
	SSH       ServiceAccess   `json:"ssh"`
	Listeners []ListenerView  `json:"listeners"`
	Summary   ExposureSummary `json:"summary"`
	CheckedAt time.Time       `json:"checkedAt"`
	Error     string          `json:"error"`
}

// ServiceAccess describes RDP or SSH.
type ServiceAccess struct {
	Available   bool `json:"available"`
	Port        int  `json:"port"`
	OverlayOnly bool `json:"overlayOnly"`
}

// ListenerView is one listening socket and how far it is reachable.
type ListenerView struct {
	Proto    string `json:"proto"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process"`
	Exposure string `json:"exposure"`
}

// ExposureSummary counts listeners by exposure.
type ExposureSummary struct {
	All       int `json:"all"`
	LAN       int `json:"lan"`
	OpenScale int `json:"openscale"`
	Local     int `json:"local"`
}
