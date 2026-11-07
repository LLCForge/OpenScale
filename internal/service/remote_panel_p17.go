package service

import (
	"context"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// runRemotePanel lets the owner open the panel from another device of the
// network (ADR-0107, F-179). The panel listens on the tunnel address only
// while this computer holds the root key, remote access is on in the
// network directory and the signed document has a panel rule for this
// device; ServeRemote checks this every few seconds.
func (r *Runtime) runRemotePanel(ctx context.Context) {
	if r.panel == nil {
		return
	}
	_ = r.panel.ServeRemote(ctx, panel.RemoteConfig{
		Self: func(doc *trust.Document) (trust.Device, bool) {
			r.mu.Lock()
			e := r.engine
			r.mu.Unlock()
			if e == nil {
				return trust.Device{}, false
			}
			self, err := e.Self()
			if err != nil {
				return trust.Device{}, false
			}
			// The owner's newest document decides, not the copy the
			// tunnel received last.
			return doc.DeviceByName(self.Name)
		},
	})
}
