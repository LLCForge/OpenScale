package panel

import (
	"crypto/ed25519"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// G2 endpoints (ADR-0180, ADR-0183): the warrant canary (sign on this
// computer, verify), sealed admin blob verification, the cross-document
// check of several coordinators and their independence. The pages that use
// them are described in docs/rakip-analizi/calisma/panel-devir-G2.md.
// Signing happens here, on the owner's computer, with the root key; the
// coordinator only stores the result.

func (s *Server) g2Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerCheck := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireNetwork(h)))
	}
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("POST /api/g2/canary/sign", ownerWrite(s.handleCanarySign))
	mux.HandleFunc("POST /api/g2/canary/verify", ownerCheck(s.handleCanaryVerify))
	mux.HandleFunc("POST /api/g2/sealed-blob/verify", ownerCheck(s.handleSealedBlobVerify))
	mux.HandleFunc("POST /api/g2/coordinators/cross-check", ownerCheck(s.handleCrossCheck))
	mux.HandleFunc("GET /api/g2/coordinators/independence", owner(s.handleIndependence))
}

// panelRootKeyFile is the sealed root key in the network directory.
const panelRootKeyFile = "root.key"

// rootPublic returns the root public key of the managed network.
func (s *Server) rootPublic() (ed25519.PublicKey, *trust.SealedRootKey, error) {
	n := s.network()
	if admin.Traveling(n.Dir()) {
		return nil, nil, admin.ErrTraveling
	}
	data, err := securefile.ReadPrivate(filepath.Join(n.Dir(), panelRootKeyFile), trust.MaxSealedKeySize)
	if err != nil {
		return nil, nil, err
	}
	sk, err := trust.UnmarshalSealedRootKey(data)
	if err != nil {
		return nil, nil, err
	}
	return sk.RootPublicKey(), sk, nil
}

type canarySignRequest struct {
	Passphrase string `json:"passphrase"`
	Statement  string `json:"statement"`
	Days       int    `json:"days"`
}

// CanaryReply describes a canary.
type CanaryReply struct {
	Schema    int       `json:"schema"`
	State     string    `json:"state"`
	Label     string    `json:"label"`
	Seq       uint64    `json:"seq,omitempty"`
	IssuedAt  time.Time `json:"issuedAt,omitzero"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
	Statement string    `json:"statement,omitempty"`
	// Canary is the signed file (base64 in JSON) after signing.
	Canary []byte `json:"canary,omitempty"`
}

func (s *Server) handleCanarySign(w http.ResponseWriter, r *http.Request) {
	var req canarySignRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pass := []byte(req.Passphrase)
	defer wipe(pass)
	if req.Days < 1 || req.Days > 90 {
		writeError(w, http.StatusBadRequest, "Geçerlilik 1 ile 90 gün arasında olmalı.")
		return
	}
	statement := strings.TrimSpace(strings.ReplaceAll(req.Statement, "\r\n", "\n"))
	if statement == "" || len(statement) > coordinator.MaxCanaryStatement {
		writeError(w, http.StatusBadRequest, "Beyan metni boş olamaz ve en çok 2000 bayt olabilir.")
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	_, sk, err := s.rootPublic()
	if err != nil {
		writeError(w, http.StatusConflict, "Kök anahtar dosyası okunamadı; kök anahtar donanım jetonundaysa kanarya henüz panelden imzalanamaz.")
		return
	}
	root, err := sk.Open(pass)
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	defer wipe(root)
	now := s.now().UTC().Truncate(time.Second)
	c := coordinator.Canary{NetworkID: doc.NetworkID, Seq: uint64(now.Unix()), IssuedAt: now, //nolint:gosec // after 1970
		NotAfter: now.Add(time.Duration(req.Days) * 24 * time.Hour), Statement: statement}
	data, err := coordinator.SignCanary(root, c)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Kanarya imzalanamadı: beyan metnini kontrol edin.")
		return
	}
	writeJSON(w, http.StatusOK, CanaryReply{Schema: 1, State: string(coordinator.CanaryValid), Label: coordinator.CanaryValid.Label(),
		Seq: c.Seq, IssuedAt: c.IssuedAt, NotAfter: c.NotAfter, Statement: c.Statement, Canary: data})
}

type canaryVerifyRequest struct {
	Canary []byte `json:"canary"`
}

func (s *Server) handleCanaryVerify(w http.ResponseWriter, r *http.Request) {
	var req canaryVerifyRequest
	if !decodeBody(w, r, &req) {
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	pub, _, err := s.rootPublic()
	if err != nil {
		s.fail(w, err)
		return
	}
	c, st, _ := coordinator.OpenCanary(req.Canary, pub, doc.NetworkID, s.now())
	reply := CanaryReply{Schema: 1, State: string(st), Label: st.Label()}
	if st != coordinator.CanaryInvalid && st != coordinator.CanaryMissing {
		reply.Seq, reply.IssuedAt, reply.NotAfter, reply.Statement = c.Seq, c.IssuedAt, c.NotAfter, c.Statement
	}
	writeJSON(w, http.StatusOK, reply)
}

type sealedBlobVerifyRequest struct {
	Blob []byte `json:"blob"`
}

// SealedBlobReply describes a verified sealed blob (never its contents).
type SealedBlobReply struct {
	Schema   int       `json:"schema"`
	Valid    bool      `json:"valid"`
	Error    string    `json:"error,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	Seq      uint64    `json:"seq,omitempty"`
	IssuedAt time.Time `json:"issuedAt,omitzero"`
	Signer   string    `json:"signer,omitempty"` // "kök" or the admin device's name
	Size     int       `json:"size,omitempty"`
}

func (s *Server) handleSealedBlobVerify(w http.ResponseWriter, r *http.Request) {
	var req sealedBlobVerifyRequest
	if !decodeBody(w, r, &req) {
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	pub, _, err := s.rootPublic()
	if err != nil {
		s.fail(w, err)
		return
	}
	b, err := coordinator.OpenSealedBlob(req.Blob, doc, pub, s.now())
	if err != nil {
		writeJSON(w, http.StatusOK, SealedBlobReply{Schema: 1, Error: "Mühürlü blob doğrulanamadı: kök veya yönetici cihaz imzası yok ya da başka ağa ait."})
		return
	}
	signer := "kök"
	if trust.Key(pub) != b.Signer {
		for _, d := range doc.Devices {
			if d.SigningKey == b.Signer {
				signer = d.Name
			}
		}
	}
	writeJSON(w, http.StatusOK, SealedBlobReply{Schema: 1, Valid: true, Kind: b.Kind, Seq: b.Seq, IssuedAt: b.IssuedAt, Signer: signer, Size: len(b.Sealed)})
}

type crossCheckRequest struct {
	Observations []coordinator.HeadObservation `json:"observations"`
	LastNewer    map[string]time.Time          `json:"lastNewer,omitempty"`
}

func (s *Server) handleCrossCheck(w http.ResponseWriter, r *http.Request) {
	var req crossCheckRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Observations) == 0 || len(req.Observations) > 16 {
		writeError(w, http.StatusBadRequest, "1 ile 16 arasında koordinatör gözlemi gönderin.")
		return
	}
	writeJSON(w, http.StatusOK, coordinator.CrossCheck(req.Observations, req.LastNewer, s.now()))
}

// IndependenceReply is GET /api/g2/coordinators/independence.
type IndependenceReply struct {
	Schema       int                       `json:"schema"`
	Coordinators []IndependenceCoordinator `json:"coordinators"`
	Findings     []coordinator.HeadFinding `json:"findings"`
}

// IndependenceCoordinator is one usable coordinator.
type IndependenceCoordinator struct {
	Label  string `json:"label"`
	Region string `json:"region,omitempty"`
}

func (s *Server) handleIndependence(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	now := s.now()
	reply := IndependenceReply{Schema: 1, Findings: coordinator.IndependenceAdvice(doc, now)}
	for _, c := range doc.UsableCoordinators(now) {
		reply.Coordinators = append(reply.Coordinators, IndependenceCoordinator{Label: c.CoordinatorLabel(), Region: c.Region})
	}
	if reply.Findings == nil {
		reply.Findings = []coordinator.HeadFinding{}
	}
	writeJSON(w, http.StatusOK, reply)
}
