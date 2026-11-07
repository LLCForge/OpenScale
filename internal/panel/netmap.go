package panel

import (
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Network map (#229): devices, the coordinator and the links between them.
// A link exists when the signed rules let traffic flow between two devices
// in at least one direction, or when the tunnel pairs them only for the
// owner's status queries (admin) or exit traffic (exit). The path of a link
// (direct or through the relay) is known only for links of this computer:
// the panel never asks other devices about their paths.

// Link path values.
const (
	pathDirect  = "direct"
	pathRelay   = "relay"
	pathNone    = "none"
	pathUnknown = "unknown"
)

// Tunnel-only link reasons.
const (
	peerAdmin = "admin"
	peerExit  = "exit"
)

type mapNode struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	IPv4         string   `json:"ipv4"`
	OS           string   `json:"os"`
	ExitNode     bool     `json:"exitNode"`
	Admin        bool     `json:"admin"`
	ThisComputer bool     `json:"thisComputer"`
	Status       string   `json:"status"`
	Tags         []string `json:"tags"`
}

type mapEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Rule: an enabled rule allows traffic in at least one direction.
	Rule bool `json:"rule"`
	// Peer is why the tunnel pairs two devices without a rule ("admin" or
	// "exit"), "" otherwise.
	Peer string `json:"peer"`
	// Path is direct, relay or none for links of this computer, unknown
	// for the others.
	Path string `json:"path"`
}

type mapResponse struct {
	Nodes []mapNode `json:"nodes"`
	Edges []mapEdge `json:"edges"`
	// Live: the paths of this computer's links are known (desktop app).
	Live bool `json:"live"`
}

// coordinatorNodeID is the map ID of the coordinator.
const coordinatorNodeID = "coordinator"

func (s *Server) handleNetworkMap(w http.ResponseWriter, _ *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, buildNetworkMap(doc, s.liveView(), s.now()))
}

// buildNetworkMap is pure apart from the live snapshot it is given.
func buildNetworkMap(doc *trust.Document, l live, now time.Time) mapResponse {
	resp := mapResponse{Nodes: []mapNode{}, Edges: []mapEdge{}, Live: l.selfName != ""}
	if c := doc.Coordinator; c != nil {
		co := l.coordinator(doc, now)
		n := mapNode{ID: coordinatorNodeID, Name: "koordinatör", Kind: "coordinator", IPv4: c.IPv4.String(), Status: co.Status, Tags: []string{}}
		if co.System != nil {
			n.OS = co.System.OS
		}
		resp.Nodes = append(resp.Nodes, n)
	}
	peers := make(map[string]map[string]bool, len(doc.Devices))
	for _, d := range doc.Devices {
		v := l.device(doc, d, now)
		n := mapNode{ID: d.ID, Name: d.Name, Kind: "device", IPv4: v.IPv4, ExitNode: v.ExitNode, Admin: v.Admin,
			ThisComputer: v.ThisComputer || (l.selfName != "" && d.Name == l.selfName), Status: v.Status, Tags: v.Tags}
		if v.System != nil {
			n.OS = v.System.OS
		}
		resp.Nodes = append(resp.Nodes, n)
		set := map[string]bool{}
		for _, p := range doc.TunnelPeersOf(d.Name) {
			set[p.Name] = true
		}
		peers[d.Name] = set
	}
	for i, a := range doc.Devices {
		for _, b := range doc.Devices[i+1:] {
			e := mapEdge{From: a.ID, To: b.ID, Rule: doc.Visible(a.Name, b.Name), Path: pathUnknown}
			if !e.Rule {
				if !peers[a.Name][b.Name] && !peers[b.Name][a.Name] {
					continue
				}
				e.Peer = peerAdmin
				if (a.HasRole(trust.RoleExitNode) || b.HasRole(trust.RoleExitNode)) && !a.HasRole(trust.RoleAdmin) && !b.HasRole(trust.RoleAdmin) {
					e.Peer = peerExit
				}
			}
			switch l.selfName {
			case "":
			case a.Name:
				e.Path = l.path(b.WireGuardKey, now)
			case b.Name:
				e.Path = l.path(a.WireGuardKey, now)
			}
			resp.Edges = append(resp.Edges, e)
		}
	}
	return resp
}

// path is how this computer reaches the device with key now.
func (l live) path(key trust.Key, now time.Time) string {
	p, ok := l.stats.Direct[key]
	if !ok || p.LastHandshake.IsZero() || now.Sub(p.LastHandshake) >= onlineWindow {
		return pathNone
	}
	if p.Relayed {
		return pathRelay
	}
	return pathDirect
}
