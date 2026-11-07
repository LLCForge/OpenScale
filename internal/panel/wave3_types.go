package panel

import "time"

// Connection wave 3: the desktop service's automatic exit node (ADR-0133,
// P10), the coordinator list it uses (ADR-0111, P15), the approval policy
// and hardware key state (ADR-0121, ADR-0123, ADR-0124, P22) and network
// profiles (ADR-0135, P28).

// HealthCoordinatorIntegrity: a coordinator served a document or a view
// that disagrees with what this device verified (ADR-0111, #154).
const HealthCoordinatorIntegrity = "coordinator_integrity"

// Limits of the automatic exit node settings.
const (
	MaxExitCandidates  = 16
	MaxTrustedWiFi     = 32
	MaxTrustedWiFiLen  = 128
	MaxExitExceptions  = 64
	ExitAutoModeOff    = ""
	ExitAutoFailover   = "failover"
	ExitAutoFastest    = "fastest"
	maxExitExceptEntry = 43
)

// ExitAutoSettings is the saved automatic exit node choice.
type ExitAutoSettings struct {
	// Mode is "", "failover" or "fastest".
	Mode string `json:"mode"`
	// Candidates are exit node names in order of preference; empty means
	// every exit node this device may use.
	Candidates []string `json:"candidates"`
	// Untrusted turns the exit node on only on networks outside the
	// trusted list.
	Untrusted   bool     `json:"untrusted"`
	TrustedWiFi []string `json:"trustedWifi"`
	TrustWired  bool     `json:"trustWired"`
	// Except are IPv4 ranges kept outside the exit node.
	Except []string `json:"except"`
}

// Enabled reports whether the automatic choice runs.
func (s ExitAutoSettings) Enabled() bool { return s.Mode != "" || s.Untrusted }

// ExitAutoState is the automatic exit node choice and what it decided.
type ExitAutoState struct {
	Settings ExitAutoSettings `json:"settings"`
	// Exit is the exit node the automatic choice uses now ("" none).
	Exit   string     `json:"exit"`
	Reason string     `json:"reason"`
	Since  *time.Time `json:"since,omitempty"`
	// Networks are the networks in use, as read for the trust decision.
	Networks []string `json:"networks"`
}

// CoordinatorState is one coordinator as this device sees it.
type CoordinatorState struct {
	Name        string     `json:"name"`
	Region      string     `json:"region"`
	Fingerprint string     `json:"fingerprint"`
	Endpoint    string     `json:"endpoint"`
	Primary     bool       `json:"primary"`
	Active      bool       `json:"active"`
	Relay       bool       `json:"relay"`
	Until       *time.Time `json:"until,omitempty"`
	RTTMillis   int64      `json:"rttMs"`
	LastReply   *time.Time `json:"lastReply,omitempty"`
	Failures    int        `json:"failures"`
}

// IntegrityNote is one finding of the coordinator integrity report.
type IntegrityNote struct {
	Severity    string `json:"severity"`
	Coordinator string `json:"coordinator,omitempty"`
	Peer        string `json:"peer,omitempty"`
	Text        string `json:"text"`
	Verified    bool   `json:"verified"`
}

// ProfileState is one network profile of this computer.
type ProfileState struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	Joined      bool   `json:"joined"`
}

// Wave3Status is the part of DeviceStatus added by connection wave 3.
type Wave3Status struct {
	// ExitAuto is set while the automatic exit node choice runs.
	ExitAuto     *ExitAutoState     `json:"exitAuto,omitempty"`
	Coordinators []CoordinatorState `json:"coordinators"`
	Integrity    []IntegrityNote    `json:"integrity"`
	Profile      string             `json:"profile"`
	Profiles     []ProfileState     `json:"profiles"`
}

// Wave3App is implemented by the desktop service. The panel checks for it
// at run time so other App implementations need not change.
type Wave3App interface {
	ExitAuto() (ExitAutoState, error)
	SetExitAuto(ExitAutoSettings) error
	SwitchProfile(name string) error
}
