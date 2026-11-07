package trust

// Remote panel access (ADR-0107, F-179).
//
// A panel rule ("service": "panel") names the devices that may open the
// management panel of the destination over the tunnel. It grants reading
// only: the root key never leaves the device that runs the panel and no
// request from another device is ever allowed to sign. Like every service
// rule it opens only its fixed TCP port, a broad "any" rule does not grant
// it and an enabled deny panel rule wins.

// AllowsPanel reports whether device from may open the read-only panel of
// device to over the tunnel.
func (doc *Document) AllowsPanel(from, to string) bool {
	return doc.serviceAllowed(ServicePanel, from, to, nil)
}
