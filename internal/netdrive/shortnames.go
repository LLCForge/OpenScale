package netdrive

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Short names (#762): "nas", "ha" or "yazici" typed alone lead to a home
// service. This file holds the name to service data; answering the names
// in MagicDNS and the panel's redirect are wired by the caller (Records
// and URL give them what they need).

// ShortNamesFile is the default file name.
const ShortNamesFile = "shortnames.json"

// Limits.
const (
	MaxShortNames  = 128
	maxShortFile   = 64 << 10
	maxShortPath   = 128
	shortNameLimit = 32
)

var shortRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// reservedShort are names that must never be answered locally: they
// belong to the system or are classic proxy auto-discovery traps.
var reservedShort = []string{"localhost", "local", "coordinator", "wpad", "isatap", "broadcasthost", "gateway", "router"}

// ShortName maps a name to a device and optionally a service port.
type ShortName struct {
	Name   string `json:"name"`
	Device string `json:"device"`
	// Port and Scheme form a web address for the panel's redirect ("ha"
	// -> http://ha-device:8123/); zero Port means a plain name.
	Port   uint16 `json:"port,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Path   string `json:"path,omitempty"`
}

// ShortNames is the table.
type ShortNames struct {
	Schema  int         `json:"schema"`
	Entries []ShortName `json:"entries"`
}

// Validate checks every entry against the signed document: the target is
// a device, and no short name shadows a device name, an alias or a
// reserved name.
func (t ShortNames) Validate(doc *trust.Document) error {
	if len(t.Entries) > MaxShortNames {
		return fmt.Errorf("en fazla %d kısa ad olabilir", MaxShortNames)
	}
	if doc == nil {
		return errors.New("ağ belgesi yok")
	}
	taken := map[string]bool{}
	for _, d := range doc.Devices {
		taken[strings.ToLower(d.Name)] = true
		for _, a := range d.Aliases {
			taken[strings.ToLower(a)] = true
		}
	}
	seen := map[string]bool{}
	for _, e := range t.Entries {
		if !shortRe.MatchString(e.Name) {
			return fmt.Errorf("kısa ad küçük harf, rakam ve tire içermeli (en fazla %d): %q", shortNameLimit, e.Name)
		}
		if slices.Contains(reservedShort, e.Name) {
			return fmt.Errorf("%q ayrılmış bir ad", e.Name)
		}
		if taken[e.Name] {
			return fmt.Errorf("%q bir cihazın adı veya takma adı; kısa ad onu gölgeleyemez", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("%q iki kez tanımlanmış", e.Name)
		}
		seen[e.Name] = true
		if _, ok := doc.DeviceByName(e.Device); !ok {
			return fmt.Errorf("%q: cihaz bulunamadı: %q", e.Name, e.Device)
		}
		switch e.Scheme {
		case "", "http", "https":
		default:
			return fmt.Errorf("%q: şema http veya https olmalı", e.Name)
		}
		if e.Port == 0 && (e.Scheme != "" || e.Path != "") {
			return fmt.Errorf("%q: şema ve yol için port gerekli", e.Name)
		}
		if e.Path != "" && (len(e.Path) > maxShortPath || !strings.HasPrefix(e.Path, "/") || strings.ContainsAny(e.Path, " \r\n\t#?\\") || strings.Contains(e.Path, "//")) {
			return fmt.Errorf("%q: yol / ile başlayan basit bir yol olmalı", e.Name)
		}
	}
	return nil
}

// Lookup finds a short name, case-insensitively.
func (t ShortNames) Lookup(name string) (ShortName, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, e := range t.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return ShortName{}, false
}

// Record is what MagicDNS answers for a short name.
type Record struct {
	Name string
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// Records returns the address records of every entry whose device exists.
func (t ShortNames) Records(doc *trust.Document) []Record {
	if doc == nil {
		return nil
	}
	var out []Record
	for _, e := range t.Entries {
		d, ok := doc.DeviceByName(e.Device)
		if !ok {
			continue
		}
		out = append(out, Record{Name: e.Name, IPv4: d.IPv4, IPv6: d.IPv6})
	}
	return out
}

// URL returns the service's web address by the device's MagicDNS name.
func (e ShortName) URL(doc *trust.Document) (string, error) {
	if e.Port == 0 {
		return "", errors.New("bu kısa ad bir web servisine bağlı değil")
	}
	if doc == nil || doc.DNSDomain == "" {
		return "", errors.New("ağın DNS alanı yok")
	}
	if _, ok := doc.DeviceByName(e.Device); !ok {
		return "", ErrWakeNoDevice
	}
	scheme := e.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := e.Path
	if path == "" {
		path = "/"
	}
	return scheme + "://" + strings.ToLower(e.Device) + "." + doc.DNSDomain + ":" + strconv.Itoa(int(e.Port)) + path, nil
}

// LoadShortNames reads the table.
func LoadShortNames(path string) (ShortNames, error) {
	data, err := securefile.ReadLimited(path, maxShortFile)
	if err != nil {
		return ShortNames{}, err
	}
	var t ShortNames
	if err := json.Unmarshal(data, &t); err != nil {
		return ShortNames{}, fmt.Errorf("kısa ad tablosu okunamadı: %w", err)
	}
	if t.Schema != 1 {
		return ShortNames{}, fmt.Errorf("kısa ad tablosu sürümü %d desteklenmiyor", t.Schema)
	}
	return t, nil
}

// SaveShortNames validates and writes the table.
func SaveShortNames(path string, doc *trust.Document, t ShortNames) error {
	t.Schema = 1
	if err := t.Validate(doc); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(path, append(data, '\n'))
}
