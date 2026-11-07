package portmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

// UPnP-IGD: SSDP discovery restricted to the gateway, the device
// description and the WANIPConnection / WANPPPConnection SOAP service.

const (
	ssdpMulticast = "239.255.255.250"
	ssdpPort      = 1900
	// ssdpTTL keeps M-SEARCH on the local network (UPnP DA 1.1 default).
	ssdpTTL = 2
	// ssdpWait bounds discovery.
	ssdpWait = 2 * time.Second
	// maxSSDPReply bounds one SSDP datagram.
	maxSSDPReply = 2048
	// maxDescription and maxSOAP bound the HTTP bodies read.
	maxDescription = 128 << 10
	maxSOAP        = 16 << 10
	// maxDeviceDepth bounds the device tree walked.
	maxDeviceDepth = 8
	// maxSOAPArgs and maxSOAPValue bound a parsed SOAP reply.
	maxSOAPArgs  = 32
	maxSOAPValue = 1024
	httpTimeout  = 3 * time.Second
)

// UPnP error codes used here (UPnP IGD WANIPConnection:1/2).
const (
	upnpNoSuchEntry      = 714
	upnpConflict         = 718
	upnpSamePortRequired = 724
	upnpOnlyPermanent    = 725
)

// serviceTypes are the WAN connection services, most preferred first.
var serviceTypes = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// searchTargets are the SSDP search targets sent.
var searchTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
}

// errForeignURL is returned for a description or control URL that is not
// on the gateway itself.
var errForeignURL = errors.New("UPnP adresi ağ geçidinde değil")

// upnpService is a discovered WAN connection service.
type upnpService struct {
	serviceType string
	controlURL  string
}

// soapFault is a UPnP error reply.
type soapFault struct {
	code int
	desc string
}

func (f *soapFault) Error() string {
	return fmt.Sprintf("UPnP hata kodu %d (%s)", f.code, f.desc)
}

// faultCode returns the UPnP error code of err, or 0.
func faultCode(err error) int {
	var f *soapFault
	if errors.As(err, &f) {
		return f.code
	}
	return 0
}

// mSearch builds one M-SEARCH request.
func mSearch(st string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + ssdpMulticast + ":" + strconv.Itoa(ssdpPort) + "\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: " + st + "\r\n\r\n")
}

// parseSSDPResponse returns the LOCATION of an SSDP search response.
func parseSSDPResponse(b []byte) (string, error) {
	if len(b) > maxSSDPReply {
		return "", errMalformed
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		return "", errMalformed
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errMalformed
	}
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if loc == "" || len(loc) > 512 {
		return "", errMalformed
	}
	return loc, nil
}

// onGateway checks that raw is an http URL whose host is the gateway's IP
// literal, and returns it parsed.
func (c *Client) onGateway(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil {
		return nil, errForeignURL
	}
	host := u.Hostname()
	a, err := netip.ParseAddr(host)
	if err != nil || a.Unmap() != c.gw {
		return nil, errForeignURL
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errForeignURL
		}
	}
	return u, nil
}

// discover finds the gateway's WAN connection service: SSDP M-SEARCH to the
// gateway (unicast) and, unless disabled, to the multicast group with TTL 2;
// only replies from the gateway's address count.
func (c *Client) discover(ctx context.Context) (*upnpService, error) {
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.local, 0)))
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { _ = pc.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	unicast := netip.AddrPortFrom(c.gw, uint16(c.opts.ssdpPort))
	for _, st := range searchTargets {
		if _, err := pc.WriteToUDPAddrPort(mSearch(st), unicast); err != nil {
			return nil, err
		}
	}
	if !c.opts.noMulticast {
		p := ipv4.NewPacketConn(pc)
		_ = p.SetMulticastTTL(ssdpTTL)
		_ = p.SetMulticastLoopback(false)
		if ifi := interfaceOf(c.local); ifi != nil {
			_ = p.SetMulticastInterface(ifi)
		}
		group := netip.AddrPortFrom(netip.MustParseAddr(ssdpMulticast), ssdpPort)
		for _, st := range searchTargets {
			_, _ = pc.WriteToUDPAddrPort(mSearch(st), group)
		}
	}
	deadline := time.Now().Add(ssdpWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = pc.SetReadDeadline(deadline)
	buf := make([]byte, maxSSDPReply+1)
	tried := map[string]bool{}
	var lastErr error = errNoReply
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, lastErr
		}
		if from.Addr().Unmap() != c.gw {
			continue // only the gateway itself may answer
		}
		loc, err := parseSSDPResponse(buf[:n])
		if err != nil || tried[loc] || len(tried) >= 4 {
			continue
		}
		tried[loc] = true
		svc, err := c.describe(ctx, loc)
		if err != nil {
			lastErr = err
			continue
		}
		return svc, nil
	}
}

// interfaceOf returns the interface that has addr, or nil.
func interfaceOf(addr netip.Addr) *net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifs {
		addrs, err := ifs[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if x, ok := netip.AddrFromSlice(ipn.IP); ok && x.Unmap() == addr {
					return &ifs[i]
				}
			}
		}
	}
	return nil
}

// httpClient talks to the gateway only: from the local address, without
// proxies or redirects.
func (c *Client) httpClient() *http.Client {
	d := &net.Dialer{Timeout: httpTimeout, LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(c.local, 0))}
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            d.DialContext,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 16 << 10,
			ResponseHeaderTimeout:  httpTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// upnpDevice and upnpServiceDesc mirror the parts of the UPnP device
// description used here. Element names match in any namespace.
type upnpRoot struct {
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	DeviceType string            `xml:"deviceType"`
	Services   []upnpServiceDesc `xml:"serviceList>service"`
	Devices    []upnpDevice      `xml:"deviceList>device"`
}

type upnpServiceDesc struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

// parseDescription finds the preferred WAN connection service in a device
// description; it returns the URL base ("" when absent) and the service.
func parseDescription(b []byte) (string, upnpServiceDesc, error) {
	var root upnpRoot
	if err := xml.Unmarshal(b, &root); err != nil {
		return "", upnpServiceDesc{}, errMalformed
	}
	found := map[string]upnpServiceDesc{}
	var walk func(d *upnpDevice, depth int)
	walk = func(d *upnpDevice, depth int) {
		if depth > maxDeviceDepth {
			return
		}
		for _, s := range d.Services {
			st := strings.TrimSpace(s.ServiceType)
			if _, ok := found[st]; !ok && strings.TrimSpace(s.ControlURL) != "" {
				found[st] = upnpServiceDesc{ServiceType: st, ControlURL: strings.TrimSpace(s.ControlURL)}
			}
		}
		for i := range d.Devices {
			walk(&d.Devices[i], depth+1)
		}
	}
	walk(&root.Device, 0)
	for _, st := range serviceTypes {
		if s, ok := found[st]; ok {
			return strings.TrimSpace(root.URLBase), s, nil
		}
	}
	return "", upnpServiceDesc{}, errors.New("UPnP aygıtında WAN bağlantı servisi yok")
}

// describe fetches the device description at loc (on the gateway) and
// returns its WAN connection service.
func (c *Client) describe(ctx context.Context, loc string) (*upnpService, error) {
	u, err := c.onGateway(loc)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UPnP aygıt tanımı: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDescription+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDescription {
		return nil, errors.New("UPnP aygıt tanımı çok büyük")
	}
	base, svc, err := parseDescription(body)
	if err != nil {
		return nil, err
	}
	ref := u
	if base != "" {
		if ref, err = c.onGateway(base); err != nil {
			return nil, err
		}
	}
	cu, err := url.Parse(svc.ControlURL)
	if err != nil {
		return nil, errForeignURL
	}
	control, err := c.onGateway(ref.ResolveReference(cu).String())
	if err != nil {
		return nil, err
	}
	return &upnpService{serviceType: svc.ServiceType, controlURL: control.String()}, nil
}

// soapArg is one argument of a SOAP action, in order.
type soapArg struct{ name, value string }

// soapBody builds the SOAP envelope of an action.
func soapBody(serviceType, action string, args []soapArg) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?>` + "\r\n")
	b.WriteString(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	b.WriteString(`<u:` + action + ` xmlns:u="`)
	_ = xml.EscapeText(&b, []byte(serviceType))
	b.WriteString(`">`)
	for _, a := range args {
		b.WriteString("<" + a.name + ">")
		_ = xml.EscapeText(&b, []byte(a.value))
		b.WriteString("</" + a.name + ">")
	}
	b.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	return b.Bytes()
}

// parseSOAPResponse returns the output arguments of a SOAP reply, or the
// UPnP fault it carries.
func parseSOAPResponse(b []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	out := map[string]string{}
	var (
		path      []string
		inBody    bool
		respDepth = -1
		fault     *soapFault
		text      strings.Builder
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errMalformed
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			if len(path) > 16 {
				return nil, errMalformed
			}
			text.Reset()
			if t.Name.Local == "Body" {
				inBody = true
			}
			if inBody && respDepth < 0 && len(path) >= 2 && path[len(path)-2] == "Body" {
				respDepth = len(path)
				if t.Name.Local == "Fault" {
					fault = &soapFault{}
				}
			}
		case xml.CharData:
			if text.Len()+len(t) > maxSOAPValue {
				return nil, errMalformed
			}
			text.Write(t)
		case xml.EndElement:
			if len(path) == 0 {
				return nil, errMalformed
			}
			name := path[len(path)-1]
			val := strings.TrimSpace(text.String())
			switch {
			case fault != nil && name == "errorCode":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, errMalformed
				}
				fault.code = n
			case fault != nil && name == "errorDescription":
				fault.desc = val
			case fault == nil && respDepth > 0 && len(path) == respDepth+1:
				if len(out) >= maxSOAPArgs {
					return nil, errMalformed
				}
				out[name] = val
			}
			text.Reset()
			path = path[:len(path)-1]
		}
	}
	if fault != nil {
		if fault.code == 0 {
			return nil, errors.New("UPnP hatası")
		}
		return nil, fault
	}
	if respDepth < 0 {
		return nil, errMalformed
	}
	return out, nil
}

// soap calls an action of the service.
func (c *Client) soap(ctx context.Context, svc *upnpService, action string, args []soapArg) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, svc.controlURL, bytes.NewReader(soapBody(svc.serviceType, action, args)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+svc.serviceType+"#"+action+`"`)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSOAP+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSOAP {
		return nil, errors.New("UPnP yanıtı çok büyük")
	}
	out, perr := parseSOAPResponse(body)
	if resp.StatusCode != http.StatusOK {
		if perr != nil {
			return nil, perr
		}
		return nil, fmt.Errorf("UPnP %s: HTTP %d", action, resp.StatusCode)
	}
	return out, perr
}

// upnpExternalIP asks for the gateway's external address.
func (c *Client) upnpExternalIP(ctx context.Context, svc *upnpService) (netip.Addr, error) {
	out, err := c.soap(ctx, svc, "GetExternalIPAddress", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(out["NewExternalIPAddress"])
	if err != nil {
		return netip.Addr{}, errors.New("UPnP dış adres geçersiz")
	}
	return a.Unmap(), nil
}

// upnpAdd adds a UDP mapping from external to the local address.
func (c *Client) upnpAdd(ctx context.Context, svc *upnpService, external uint16, lease time.Duration) error {
	_, err := c.soap(ctx, svc, "AddPortMapping", []soapArg{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(external))},
		{"NewProtocol", "UDP"},
		{"NewInternalPort", strconv.Itoa(int(c.port))},
		{"NewInternalClient", c.local.String()},
		{"NewEnabled", "1"},
		{"NewPortMappingDescription", c.opts.Description},
		{"NewLeaseDuration", strconv.Itoa(int(lease / time.Second))},
	})
	return err
}

// upnpOwned reports whether the gateway still maps external to this
// device's port.
func (c *Client) upnpOwned(ctx context.Context, svc *upnpService, external uint16) (bool, error) {
	out, err := c.soap(ctx, svc, "GetSpecificPortMappingEntry", []soapArg{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(external))},
		{"NewProtocol", "UDP"},
	})
	if faultCode(err) == upnpNoSuchEntry {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	client, cerr := netip.ParseAddr(out["NewInternalClient"])
	port, perr := strconv.Atoi(out["NewInternalPort"])
	return cerr == nil && perr == nil && client.Unmap() == c.local && port == int(c.port), nil
}

// upnpDelete removes the mapping.
func (c *Client) upnpDelete(ctx context.Context, svc *upnpService, external uint16) error {
	_, err := c.soap(ctx, svc, "DeletePortMapping", []soapArg{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(external))},
		{"NewProtocol", "UDP"},
	})
	if faultCode(err) == upnpNoSuchEntry {
		return nil
	}
	return err
}
