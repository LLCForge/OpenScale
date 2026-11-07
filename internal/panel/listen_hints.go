package panel

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Listening services of a device (F-220, ADR-0108). The device's system
// report lists the TCP ports it listens on outside loopback; the panel
// names the well-known ones and checks the signed rules: which devices may
// reach the port through the tunnel. The list never reaches the
// coordinator; reports come only to admin devices (ADR-0015).

// knownService describes a well-known TCP port.
type knownService struct {
	name  string
	risky bool
}

// knownServices are the ports worth a hint. risky marks remote login,
// file sharing and databases that should not be open without a reason.
var knownServices = map[uint16]knownService{
	21:    {"FTP", true},
	22:    {"SSH", true},
	23:    {"Telnet", true},
	25:    {"SMTP", false},
	53:    {"DNS", false},
	80:    {"HTTP", false},
	139:   {"NetBIOS", true},
	443:   {"HTTPS", false},
	445:   {"SMB (dosya paylaşımı)", true},
	548:   {"AFP (dosya paylaşımı)", true},
	631:   {"IPP (yazıcı)", false},
	1433:  {"Microsoft SQL Server", true},
	2049:  {"NFS", true},
	2375:  {"Docker API (şifresiz)", true},
	3306:  {"MySQL", true},
	3389:  {"RDP (uzak masaüstü)", true},
	5432:  {"PostgreSQL", true},
	5900:  {"VNC", true},
	5985:  {"WinRM", true},
	6379:  {"Redis", true},
	8080:  {"HTTP (alternatif)", false},
	9200:  {"Elasticsearch", true},
	11211: {"memcached", true},
	27017: {"MongoDB", true},
}

// openScalePorts are OpenScale's own service ports.
var openScalePorts = map[uint16]string{
	trust.SSHPort:           "OpenScale SSH",
	trust.FilesPort:         "OpenScale dosya gönderme",
	trust.SpeedtestPort:     "OpenScale hız testi",
	trust.WakePort:          "OpenScale uyandırma",
	trust.RemoteDesktopPort: "OpenScale uzak masaüstü",
	4048:                    "OpenScale mesajlaşma",
	trust.SyncPort:          "OpenScale klasör eşitleme",
	trust.PanelPort:         "OpenScale uzak panel",
	trust.FilesE2EPort:      "OpenScale uçtan uca dosya gönderme",
}

// maxReachableNames bounds the device names listed per port.
const maxReachableNames = 32

// ListeningService is one listening port and what the rules say about it.
type ListeningService struct {
	Port uint16 `json:"port"`
	Name string `json:"name,omitempty"`
	// Risky marks remote login, file sharing and database ports.
	Risky bool `json:"risky"`
	// OpenScale marks OpenScale's own service ports.
	OpenScale bool `json:"openscale"`
	// ReachableFrom lists devices whose rules allow TCP to this port
	// through the tunnel (at most 32 names).
	ReachableFrom []string `json:"reachable_from"`
	Hint          string   `json:"hint,omitempty"`
}

// ServicesReply is GET /api/v1/devices/{name}/services.
type ServicesReply struct {
	Schema   int                `json:"schema"`
	Device   string             `json:"device"`
	Reported bool               `json:"reported"`
	At       *time.Time         `json:"at,omitempty"`
	Services []ListeningService `json:"services"`
}

// listeningServices builds the hints for the ports of device dev.
func listeningServices(doc *trust.Document, dev trust.Device, ports []uint16) []ListeningService {
	out := make([]ListeningService, 0, len(ports))
	for _, p := range ports {
		ls := ListeningService{Port: p, ReachableFrom: []string{}}
		if name, ok := openScalePorts[p]; ok {
			ls.Name, ls.OpenScale = name, true
		} else if k, ok := knownServices[p]; ok {
			ls.Name, ls.Risky = k.name, k.risky
		}
		for _, d := range doc.Devices {
			if d.Name == dev.Name || !doc.Allows(d.Name, dev.Name, trust.ProtocolTCP, p) {
				continue
			}
			if len(ls.ReachableFrom) < maxReachableNames {
				ls.ReachableFrom = append(ls.ReachableFrom, d.Name)
			}
		}
		ls.Hint = serviceHint(dev.Name, ls)
		out = append(out, ls)
	}
	return out
}

func serviceHint(device string, ls ListeningService) string {
	label := ls.Name
	if label == "" {
		label = "Bilinmeyen servis"
	}
	switch {
	case ls.OpenScale:
		return ""
	case len(ls.ReachableFrom) == 0 && ls.Risky:
		return fmt.Sprintf("%s cihazında %s (%d) açık ama hiçbir kural tünelden erişime izin vermiyor. Gerekmiyorsa servisi kapat; gerekiyorsa yalnızca ihtiyaç duyan cihaza kural ekle.", device, label, ls.Port)
	case len(ls.ReachableFrom) == 0:
		return ""
	case ls.Risky:
		return fmt.Sprintf("%s (%d) tünelden şu cihazlara açık: %s. Kuralın gerçekten gerekli olduğunu doğrula.", label, ls.Port, strings.Join(ls.ReachableFrom, ", "))
	default:
		return fmt.Sprintf("%s (%d) tünelden şu cihazlara açık: %s.", label, ls.Port, strings.Join(ls.ReachableFrom, ", "))
	}
}

func (s *Server) v1DeviceServices(w http.ResponseWriter, r *http.Request) {
	doc, dev, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	if s.app == nil {
		v1Error(w, r, http.StatusConflict, "Cihaz raporları yalnızca OpenScale servisi çalışırken toplanır.")
		return
	}
	inv := s.app.Inventory()
	reply := ServicesReply{Schema: APISchema, Device: dev.Name, Services: []ListeningService{}}
	var rep *Report
	if got, found := inv.Devices[dev.Name]; found {
		rep = &got
	} else if inv.Self != nil && s.isSelf(doc, dev) {
		rep = inv.Self
	}
	if rep != nil && rep.Info.OS != "" {
		at := rep.At
		reply.Reported, reply.At = true, &at
		reply.Services = listeningServices(doc, dev, rep.Info.Listen)
	}
	writeJSON(w, http.StatusOK, reply)
}

// isSelf reports whether dev is this computer: the only device the
// inventory has no remote report for.
func (s *Server) isSelf(doc *trust.Document, dev trust.Device) bool {
	if self, ok := SelfByInterfaces(doc); ok {
		return self.Name == dev.Name
	}
	return false
}
