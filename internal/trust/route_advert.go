package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Route advertisements (ADR-0133, F-033, #258). A router device states the
// ranges it can forward in a message signed with its own signing key and
// hands the single-line text to the owner. The owner checks it against the
// document, chooses what to approve and signs the next document with the
// root key. The advertisement itself grants nothing: only routes in the
// signed document are valid, and there is no automatic approval.

// RouteAdvertisementContext is the signature context of route
// advertisements.
const RouteAdvertisementContext = "openscale/route-advertisement/v1"

// Route advertisement limits.
const (
	routeAdvertPrefix = "osroute1."
	// maxRouteAdvertText bounds the text form.
	maxRouteAdvertText = 8192
	// MaxRouteAdvertAge is how long an advertisement can be approved.
	MaxRouteAdvertAge = 30 * 24 * time.Hour
	// routeAdvertSkew tolerates a router clock slightly ahead.
	routeAdvertSkew = 10 * time.Minute
)

// Route advertisement errors.
var (
	ErrRouteAdvertExpired = errors.New("rota ilanı çok eski veya ileri tarihli")
	ErrRouteAdvertDevice  = errors.New("rota ilanı bu ağın bir cihazından değil")
)

// RouteAdvertisement is the signed payload of a route request.
type RouteAdvertisement struct {
	NetworkID string         `json:"network_id"`
	DeviceID  string         `json:"device_id"`
	Routes    []netip.Prefix `json:"routes"`
	IssuedAt  time.Time      `json:"issued_at"`
}

func (a *RouteAdvertisement) check() error {
	if !isValidID(a.NetworkID) || !isValidID(a.DeviceID) {
		return errors.New("route advertisement ids are invalid")
	}
	if len(a.Routes) == 0 || len(a.Routes) > MaxDeviceRoutes {
		return fmt.Errorf("route advertisement needs 1-%d routes", MaxDeviceRoutes)
	}
	for _, p := range a.Routes {
		if err := validateRoutePrefix(p); err != nil {
			return err
		}
	}
	if a.IssuedAt.IsZero() {
		return errors.New("route advertisement has no time")
	}
	return nil
}

// NewRouteAdvertisement signs a route request with the device's signing
// key and returns its text form "osroute1.<base64url>".
func NewRouteAdvertisement(secrets *DeviceSecrets, networkID, deviceID string, routes []netip.Prefix, now time.Time) (string, error) {
	if secrets == nil {
		return "", errors.New("device keys are missing")
	}
	a := RouteAdvertisement{NetworkID: networkID, DeviceID: deviceID, Routes: normalizeRoutes(routes), IssuedAt: now.UTC().Truncate(time.Second)}
	if err := a.check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	env, err := Sign(secrets.SigningKey(), RouteAdvertisementContext, payload)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	line := routeAdvertPrefix + base64.RawURLEncoding.EncodeToString(data)
	if len(line) > maxRouteAdvertText {
		return "", errors.New("route advertisement is too large")
	}
	return line, nil
}

// DecodeRouteAdvertisement parses the text form without verifying it.
func DecodeRouteAdvertisement(line string) (Envelope, error) {
	line = strings.TrimSpace(line)
	if len(line) > maxRouteAdvertText || !strings.HasPrefix(line, routeAdvertPrefix) {
		return Envelope{}, errors.New("not a route advertisement")
	}
	data, err := base64.RawURLEncoding.DecodeString(line[len(routeAdvertPrefix):])
	if err != nil {
		return Envelope{}, errors.New("not a route advertisement")
	}
	var env Envelope
	if err := decodeStrict(data, &env); err != nil {
		return Envelope{}, errors.New("not a route advertisement")
	}
	if env.Context != RouteAdvertisementContext {
		return Envelope{}, ErrWrongContext
	}
	return env, nil
}

// OpenRouteAdvertisement verifies the text form against the device that
// signed it and returns the request and that device. It does not change
// the document.
func (doc *Document) OpenRouteAdvertisement(line string, now time.Time) (*RouteAdvertisement, Device, error) {
	env, err := DecodeRouteAdvertisement(line)
	if err != nil {
		return nil, Device{}, err
	}
	// The device id is read before the signature check only to find the
	// key; nothing else is trusted until the signature verifies.
	var hint RouteAdvertisement
	if err := json.Unmarshal(env.Payload, &hint); err != nil {
		return nil, Device{}, errors.New("not a route advertisement")
	}
	var dev Device
	found := false
	for _, d := range doc.Devices {
		if d.ID == hint.DeviceID {
			dev, found = d, true
			break
		}
	}
	if !found {
		return nil, Device{}, ErrRouteAdvertDevice
	}
	payload, err := env.Verify(ed25519.PublicKey(dev.SigningKey[:]), RouteAdvertisementContext)
	if err != nil {
		return nil, Device{}, err
	}
	var a RouteAdvertisement
	if err := decodeStrict(payload, &a); err != nil {
		return nil, Device{}, errors.New("route advertisement payload is invalid")
	}
	if err := a.check(); err != nil {
		return nil, Device{}, err
	}
	if a.NetworkID != doc.NetworkID || a.DeviceID != dev.ID {
		return nil, Device{}, ErrRouteAdvertDevice
	}
	if a.IssuedAt.After(now.Add(routeAdvertSkew)) || now.Sub(a.IssuedAt) > MaxRouteAdvertAge {
		return nil, Device{}, ErrRouteAdvertExpired
	}
	return &a, dev, nil
}

// ApproveRouteAdvertisement adds the advertised routes to the device. only,
// when not empty, approves just those routes; each must be advertised.
func (doc *Document) ApproveRouteAdvertisement(line string, only []netip.Prefix, now time.Time) (Device, []netip.Prefix, error) {
	a, dev, err := doc.OpenRouteAdvertisement(line, now)
	if err != nil {
		return Device{}, nil, err
	}
	routes := a.Routes
	if len(only) > 0 {
		for _, p := range only {
			ok := false
			for _, r := range a.Routes {
				ok = ok || r == p
			}
			if !ok {
				return Device{}, nil, fmt.Errorf("route %s was not advertised", p)
			}
		}
		routes = normalizeRoutes(only)
	}
	if err := doc.ApproveRoutes(dev.Name, routes); err != nil {
		return Device{}, nil, err
	}
	return dev, routes, nil
}
