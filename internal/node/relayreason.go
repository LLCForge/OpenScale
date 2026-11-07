package node

import (
	"fmt"

	"github.com/openscale/openscale/internal/trust"
)

// Why a peer is reached through the relay (#394). #253 diagnoses the
// network as a whole; this explains one peer and names what would fix it.
// The codes are stable for the panel; the hints are shown as they are.
const (
	RelayReasonForced        = "forced"
	RelayReasonUDPBlocked    = "udp_blocked"
	RelayReasonNoCandidates  = "no_candidates"
	RelayReasonDirectTimeout = "direct_timeout"
)

type relayReasonInput struct {
	forced       bool
	coordOverTCP bool
	// haveCandidate: the peer has an observed endpoint or candidates.
	haveCandidate bool
	// failures counts direct tries that ended back on the relay.
	failures int
}

// relayReason returns the reason code and a fix hint.
func relayReason(in relayReasonInput) (string, string) {
	switch {
	case in.forced:
		return RelayReasonForced, "Aktarıcı zorunlu ayarı açık; doğrudan yol hiç denenmiyor. Ayarı kapatırsanız doğrudan yol denenir."
	case in.coordOverTCP:
		return RelayReasonUDPBlocked, "Bu ağ UDP'yi engelliyor; koordinatöre TCP ile bağlanılıyor ve eşlere yalnızca aktarıcıdan ulaşılabiliyor. UDP'ye izin veren bir ağda doğrudan yol kendiliğinden denenir."
	case !in.haveCandidate:
		return RelayReasonNoCandidates, "Karşı cihazın ulaşılabilir bir adresi bilinmiyor. Karşı cihazda statik uç nokta (--static-endpoint) tanımlamak veya yönlendiricide port eşlemeyi açmak doğrudan yolu sağlayabilir."
	default:
		h := "Doğrudan deneme yanıtsız kaldı; iki tarafta da zor (simetrik) NAT veya UDP süzen bir güvenlik duvarı olabilir. Taraflardan birinde port eşleme veya statik uç nokta doğrudan yolu açar."
		if in.failures > 1 {
			h = fmt.Sprintf("Doğrudan yol %d kez denendi ve yanıt alınamadı; iki tarafta da zor (simetrik) NAT veya UDP süzen bir güvenlik duvarı olabilir. Taraflardan birinde port eşleme veya statik uç nokta doğrudan yolu açar.", in.failures)
		}
		return RelayReasonDirectTimeout, h
	}
}

// relayReasonFor explains a relayed peer; snap is its probe state.
func (e *Engine) relayReasonFor(key trust.Key, snap probeSnapshot, haveSnap bool) (string, string) {
	in := relayReasonInput{forced: e.cfg.ForceRelay, coordOverTCP: e.CoordinatorOverTCP()}
	if haveSnap {
		in.haveCandidate = snap.observed.IsValid() || len(snap.cands) > 0
	}
	e.mu.Lock()
	if ps := e.paths[key]; ps != nil {
		in.failures = ps.failures
	}
	e.mu.Unlock()
	return relayReason(in)
}
