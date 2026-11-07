package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode"
	"unicode/utf8"
)

// Hook names a decision point a plugin may join (docs/eklenti-abi.md).
const (
	HookDNS          = "dns"
	HookHTTPLocation = "http_location"
)

// Data classes a plugin may see (#790). A plugin that declares none sees
// nothing; the framework never hands it data it did not declare.
const (
	DataDNSName      = "dns_name"
	DataClientTags   = "client_tags"
	DataHTTPLocation = "http_location"
)

// On-error policies chosen by the owner in the manifest: what a failing
// plugin (timeout, trap, bad output) contributes to the decision.
const (
	OnErrorPass  = "pass"  // the plugin abstains; other layers decide
	OnErrorAllow = "allow" // DNS: answer normally, overriding later plugins
	OnErrorBlock = "block" // DNS: block the name
)

// Manifest limits.
const (
	MaxManifestSize   = 8 << 10
	maxNameLen        = 32
	maxVersionLen     = 32
	maxDescriptionLen = 280
)

var (
	knownHooks = []string{HookDNS, HookHTTPLocation}
	knownData  = []string{DataDNSName, DataClientTags, DataHTTPLocation}
	knownOnErr = []string{OnErrorPass, OnErrorAllow, OnErrorBlock}
)

// dataLabels are the panel texts of the data classes (#790).
var dataLabels = map[string]string{
	DataDNSName:      "DNS sorgu adı ve kayıt türü",
	DataClientTags:   "istemci etiketleri",
	DataHTTPLocation: "HTTP Location",
}

// NothingLabel is shown for a plugin that sees no data at all.
const NothingLabel = "hiçbir şey"

// Manifest is the owner-written description of a plugin, stored next to
// its module as <name>.json and pinned by digest in the signed document.
type Manifest struct {
	ABI         int      `json:"abi"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Hooks       []string `json:"hooks"`
	Data        []string `json:"data"`
	OnError     string   `json:"on_error"`
}

// ParseManifest reads and validates a manifest. Unknown fields, trailing
// data and inconsistent declarations are refused.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifestSize {
		return m, fmt.Errorf("plugin: manifest larger than %d bytes", MaxManifestSize)
	}
	if !utf8.Valid(b) {
		return m, errors.New("plugin: manifest is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("plugin: manifest: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("plugin: manifest: trailing data")
	}
	if m.Hooks == nil {
		m.Hooks = []string{}
	}
	if m.Data == nil {
		m.Data = []string{}
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate checks every field and the consistency of hooks and data
// classes: a hook needs its data class and a data class needs a hook that
// carries it.
func (m Manifest) Validate() error {
	if m.ABI != ABIVersion {
		return fmt.Errorf("plugin: manifest abi %d, want %d", m.ABI, ABIVersion)
	}
	if !validName(m.Name) {
		return errors.New("plugin: manifest name must be 1-32 of a-z, 0-9 and '-', starting with a letter or digit")
	}
	if !validVersion(m.Version) {
		return errors.New("plugin: manifest version must be 1-32 of letters, digits and . + -")
	}
	if len(m.Description) > maxDescriptionLen {
		return fmt.Errorf("plugin: manifest description longer than %d bytes", maxDescriptionLen)
	}
	for _, r := range m.Description {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return errors.New("plugin: manifest description has a control character")
		}
	}
	if err := checkSet("hooks", m.Hooks, knownHooks); err != nil {
		return err
	}
	if err := checkSet("data", m.Data, knownData); err != nil {
		return err
	}
	if !slices.Contains(knownOnErr, m.OnError) {
		return errors.New("plugin: manifest on_error must be pass, allow or block")
	}
	dns, httpLoc := m.HasHook(HookDNS), m.HasHook(HookHTTPLocation)
	if dns != m.Sees(DataDNSName) {
		return errors.New("plugin: manifest: hook dns and data dns_name go together")
	}
	if httpLoc != m.Sees(DataHTTPLocation) {
		return errors.New("plugin: manifest: hook http_location and data http_location go together")
	}
	if m.Sees(DataClientTags) && !dns {
		return errors.New("plugin: manifest: data client_tags needs hook dns")
	}
	return nil
}

func checkSet(field string, v, known []string) error {
	if len(v) > len(known) {
		return fmt.Errorf("plugin: manifest %s: too many entries", field)
	}
	for i, s := range v {
		if !slices.Contains(known, s) {
			return fmt.Errorf("plugin: manifest %s: unknown entry %q", field, truncate(s, 40))
		}
		if slices.Contains(v[:i], s) {
			return fmt.Errorf("plugin: manifest %s: duplicate entry %q", field, s)
		}
	}
	return nil
}

// HasHook reports whether the manifest declares hook h.
func (m Manifest) HasHook(h string) bool { return slices.Contains(m.Hooks, h) }

// Sees reports whether the manifest declares data class d.
func (m Manifest) Sees(d string) bool { return slices.Contains(m.Data, d) }

// DataLabels returns the Turkish panel labels of what the plugin sees, in
// a fixed order, or NothingLabel alone (#790).
func (m Manifest) DataLabels() []string {
	var out []string
	for _, d := range knownData {
		if m.Sees(d) {
			out = append(out, dataLabels[d])
		}
	}
	if len(out) == 0 {
		return []string{NothingLabel}
	}
	return out
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > maxNameLen || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validVersion(s string) bool {
	if len(s) == 0 || len(s) > maxVersionLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
