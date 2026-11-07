package portmap

import (
	"net/netip"
	"testing"
)

func FuzzParsePCP(f *testing.F) {
	var nonce [pcpNonceLen]byte
	req := pcpMapRequest(netip.MustParseAddr("192.168.1.10"), nonce, 51820, netip.AddrPort{}, 7200)
	resp := append([]byte(nil), req...)
	resp[1] |= pcpResponseBit
	f.Add(resp)
	f.Add(pcpAnnounceRequest(netip.MustParseAddr("192.168.1.10")))
	f.Add([]byte{0, 0x81, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parsePCPResponse(b)
		if err == nil && r.op == pcpOpMap && r.result == pcpSuccess && len(b) < pcpHeaderLen+pcpMapLen {
			t.Fatal("short MAP success accepted")
		}
	})
}

func FuzzParseNATPMP(f *testing.F) {
	f.Add([]byte{0, 128, 0, 0, 0, 0, 0, 5, 203, 0, 113, 7})
	f.Add([]byte{0, 129, 0, 0, 0, 0, 0, 5, 0xca, 0x6c, 0xca, 0x6c, 0, 0, 0x1c, 0x20})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseNATPMPResponse(b)
		if err == nil && r.result == 0 && r.op == natpmpOpExternal && !r.external.Is4() {
			t.Fatal("external address not IPv4")
		}
	})
}

func FuzzParseSSDP(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nST: upnp:rootdevice\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		loc, err := parseSSDPResponse(b)
		if err == nil && (loc == "" || len(loc) > 512) {
			t.Fatalf("bad location %q", loc)
		}
	})
}

func FuzzParseDescription(f *testing.F) {
	f.Add([]byte(testDescription))
	f.Add([]byte(`<root><device><deviceList><device><deviceList><device></device></deviceList></device></deviceList></device></root>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxDescription {
			return
		}
		_, svc, err := parseDescription(b)
		if err == nil && svc.ControlURL == "" {
			t.Fatal("service without control URL")
		}
	})
}

func FuzzParseSOAP(f *testing.F) {
	f.Add([]byte(soapReply("GetExternalIPAddress", "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>")))
	f.Add([]byte(soapFaultReply(718, "ConflictInMappingEntry")))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxSOAP {
			return
		}
		out, err := parseSOAPResponse(b)
		if err == nil && len(out) > maxSOAPArgs {
			t.Fatal("too many arguments")
		}
	})
}
