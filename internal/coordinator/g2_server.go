package coordinator

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// G2 glue (ADR-0180..ADR-0184): the hardening options, the signed object
// store, port hiding, the no-metadata sweep, the emergency priority and the
// clone sweep are attached to the server here; server.go only calls the
// hooks below.

// g2Features are announced in the caps reply next to the older features.
var g2Features = []string{FeatureSealedBlob, FeatureCanary, FeatureHead, FeatureNoLog}

func init() { coordFeatures = append(coordFeatures, g2Features...) }

// cloneSweepEvery is how often every device's endpoint is sampled for clone
// detection (#603), not only when the device sends a request.
const cloneSweepEvery = 30 * time.Second

type g2State struct {
	hard      Hardening
	spa       *spaGate
	objects   *objectStore
	stateFS   string
	swap      bool
	coreDumps string
	emerg     emergencyState
	lastSweep time.Time
	lastClone time.Time
}

// initG2 loads the hardening options and applies the ones that act at start.
func (s *Server) initG2() error {
	s.g2 = &g2State{}
	h := Hardening{Schema: hardeningSchema}
	if s.cfg.Hardening != nil {
		h = *s.cfg.Hardening
		h.Schema = hardeningSchema
		if err := h.Validate(); err != nil {
			return err
		}
	} else if dir := s.cfg.Store.Dir(); dir != "" {
		var err error
		if h, err = LoadHardening(dir); err != nil {
			return err
		}
	}
	s.g2.hard = h
	if h.Blind {
		s.relay.blind = s.blind
	}
	// #638: no core dumps and no ptrace from the same user, checked again
	// here because the coordinator holds its WireGuard key in memory.
	s.g2.coreDumps = ensureNoCoreDumps()
	if h.NoMetadata || h.Blind {
		s.logger = slog.New(newRedactHandler(s.logger.Handler()))
		s.cfg.Logger = s.logger
	}
	fsName, ram, err := stateFileSystem(s.cfg.Store.Dir())
	s.g2.stateFS = fsName
	s.g2.swap = swapActive()
	if h.RAMOnly {
		switch {
		case err != nil:
			return fmt.Errorf("RAM kipi: durum klasörünün dosya sistemi okunamadı: %w", err)
		case !ram:
			return fmt.Errorf("RAM kipi açık ama durum klasörü %q üzerinde, tmpfs/ramfs değil; diske yazmamak için başlatılmadı", fsName)
		}
		if s.g2.swap {
			s.logger.Warn("RAM kipi: sistemde takas alanı açık; bellek sayfaları diske yazılabilir")
		}
	}
	if h.SPA {
		doc := s.cfg.Store.Document()
		if doc == nil {
			return ErrSPAWithoutDocument
		}
		s.g2.spa = newSPAGate(SPAKey(s.wgKey, doc.NetworkID), s.cfg.Now)
	}
	s.g2.objects = newObjectStore(s.cfg.Store.Dir())
	doc, root, now := s.cfg.Store.Document(), s.rootKey(), s.cfg.Now()
	if err := s.g2.objects.load("canary", canaryPolicy, doc, root, now); err != nil {
		s.logger.Warn("stored canary dropped", "error", err.Error())
	}
	for _, err := range s.g2.objects.loadBlobs(doc, root, now) {
		s.logger.Warn("stored sealed blob dropped", "error", err.Error())
	}
	return nil
}

func (s *Server) rootKey() ed25519.PublicKey { return s.cfg.Store.Anchor().RootKey }

// wrapSPA puts the port-hiding gate on the UDP path (outermost, so the
// who-am-I echo is hidden as well).
func (s *Server) wrapSPA(b conn.Bind) conn.Bind {
	if s.g2 == nil || s.g2.spa == nil {
		return b
	}
	return &spaBind{Bind: b, gate: s.g2.spa}
}

// SPAStats returns the port-hiding counters (zero when off).
func (s *Server) SPAStats() SPAStats {
	if s.g2 == nil {
		return SPAStats{}
	}
	return s.g2.spa.stats()
}

// g2Tick runs every reconcile interval (one minute).
func (s *Server) g2Tick() {
	now := s.cfg.Now()
	s.g2.objects.prune(now)
	if s.g2.spa != nil {
		s.g2.spa.prune()
	}
	s.metadataSweep()
}

// g2Second runs every second: emergency pushes and the clone sweep.
func (s *Server) g2Second() {
	s.emergencyTick()
	now := s.cfg.Now()
	if now.Sub(s.g2.lastClone) >= cloneSweepEvery {
		s.g2.lastClone = now
		s.cloneSweep()
	}
}

// handleG2 answers the G2 message types for a member.
func (s *Server) handleG2(req control.Message, doc *trust.Document, self *trust.Device, src netip.Addr) (control.Message, bool) {
	now := s.cfg.Now()
	switch req.T {
	case TypeCanary:
		return s.g2.objects.read(TypeCanary, "canary", req), true
	case TypeCanaryPut:
		resp, stored := s.g2.objects.put(TypeCanaryPut, "canary", req, src, canaryPolicy, doc, s.rootKey(), now)
		if stored {
			s.logger.Info("warrant canary stored", "seq", resp.Version)
		}
		return resp, true
	case TypeSealedBlob, TypeSealedBlobPut:
		if !ValidBlobKind(req.Target) {
			return control.Message{T: control.TypeError, Error: "bad kind"}, true
		}
		slot := "blob:" + req.Target
		if req.T == TypeSealedBlob {
			return s.g2.objects.read(TypeSealedBlob, slot, req), true
		}
		resp, stored := s.g2.objects.put(TypeSealedBlobPut, slot, req, src, sealedBlobPolicy(req.Target), doc, s.rootKey(), now)
		if stored {
			s.logger.Info("sealed admin blob stored", "kind", req.Target, "seq", resp.Version)
		}
		return resp, true
	case TypeHead:
		return s.head(), true
	case TypeNoLog:
		if !self.HasRole(trust.RoleAdmin) {
			return control.Message{T: control.TypeError, Error: "not allowed"}, true
		}
		data, err := s.noLogData()
		if err != nil || len(data) > control.ChunkSize {
			return control.Message{T: control.TypeError, Error: "attestation unavailable"}, true
		}
		return control.Message{T: TypeNoLog, Data: data, Complete: true}, true
	}
	return control.Message{}, false
}

// errQuarantined is the reply to a quarantined identity.
const errQuarantined = "bu cihaz kimliği aynı anda iki yerde görüldü; sahip anahtarı yenileyene kadar koordinatör yanıt vermiyor"

// quarantineGate refuses requests from a cloned identity (#603) when the
// owner turned clone quarantine on. Leaving, version reports and caps stay
// allowed so the device can still be told why.
func (s *Server) quarantineGate(req control.Message, self *trust.Device) string {
	if s.g2 == nil || !s.g2.hard.CloneQuarantine {
		return ""
	}
	switch req.T {
	case control.TypeLeave, control.TypeClientVersion, control.TypeCaps:
		return ""
	}
	if s.cloneQuarantined(self.ID) {
		return errQuarantined
	}
	return ""
}
