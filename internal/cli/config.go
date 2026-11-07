package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/securefile"
)

// Environment variables and configuration files (F-147). For the two
// long-running commands, "up" and "coordinator run", every flag in the
// lists below may also come from an OPENSCALE_<FLAG> environment variable
// (dashes become underscores, upper case: --listen-port is
// OPENSCALE_LISTEN_PORT) or from a JSON file given with --config (or
// OPENSCALE_CONFIG), whose keys are the flag names. Order of precedence:
// command line, then environment, then the file, then the built-in
// default. Unknown keys in the file are refused, so a typo never passes
// silently. Secrets are not accepted from either source: these commands
// read their keys from the state directory only.

const (
	envPrefix     = "OPENSCALE_"
	envConfigFile = "OPENSCALE_CONFIG"
	maxConfigFile = 64 << 10
)

// lookupEnv is os.LookupEnv; tests replace it.
var lookupEnv = os.LookupEnv

// upEnvFlags are the flags of "openscale up" that environment variables
// and the configuration file may set.
var upEnvFlags = []string{
	"state-dir", "network-dir", "listen-port", "interface", "exit-node", "exit-dns-upstream", "exit-upstream",
	"netfilter-mode", "mtu", "force-relay", "relay-after", "direct-retry", "network-dns", "debug",
	"static-endpoint", "hide-local-candidates", "candidate-skip-interfaces", "disable-udp-offload",
	"magicdns-all-devices", "disable-captive-check", "conntrack-tcp-timeout", "conntrack-udp-timeout",
	"conntrack-icmp-timeout", "conntrack-other-timeout", "conntrack-max-flows", "conntrack-max-fragments",
	"local-api",
	"post-quantum", "psk-rotation", "tcp-fallback", "disable-tcp-fallback",
	"keepalive", "adaptive-keepalive", "lazy-peers", "lazy-idle",
	"sealed-candidates", "birthday-scan", "parser-sandbox", // ADR-0230, ADR-0231, ADR-0233
}

// coordinatorEnvFlags are the same for "openscale coordinator run".
var coordinatorEnvFlags = []string{"state-dir", "listen-port", "relay-rate", "relay-burst", "debug",
	"tcp-listen", "tcp-max-conns", "tcp-max-conns-per-ip"}

// EnvName is the environment variable of a flag.
func EnvName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// configFlagFrom finds --config in args without parsing the rest.
func configFlagFrom(args []string) (string, bool, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		if hasVal {
			return val, true, nil
		}
		if i+1 >= len(args) {
			return "", false, usageError("--config bir dosya yolu ister")
		}
		return args[i+1], true, nil
	}
	return "", false, nil
}

// configValues reads a JSON configuration file into flag values. Arrays
// are allowed only for list flags; nested objects never.
func configValues(path string, allowed []string) (map[string][]string, error) {
	if err := checkConfigFilePerm(path); err != nil {
		return nil, err
	}
	data, err := securefile.ReadLimited(path, maxConfigFile)
	if err != nil {
		return nil, fmt.Errorf("yapılandırma dosyası okunamadı: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("yapılandırma dosyası geçerli bir JSON nesnesi değil: %w", err)
	}
	if dec.More() {
		return nil, errors.New("yapılandırma dosyasında tek bir JSON nesnesi olmalı")
	}
	out := map[string][]string{}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !contains(allowed, k) {
			return nil, fmt.Errorf("yapılandırma dosyasında bilinmeyen alan %q; geçerli alanlar: %s", k, strings.Join(allowed, ", "))
		}
		vals, err := jsonFlagValues(raw[k])
		if err != nil {
			return nil, fmt.Errorf("yapılandırma alanı %q: %w", k, err)
		}
		out[k] = vals
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// jsonFlagValues turns a JSON scalar (or an array of scalars) into flag
// text.
func jsonFlagValues(raw json.RawMessage) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	scalar := func(x any) (string, error) {
		switch t := x.(type) {
		case string:
			return t, nil
		case bool:
			return strconv.FormatBool(t), nil
		case json.Number:
			return t.String(), nil
		}
		return "", errors.New("değer metin, sayı veya true/false olmalı")
	}
	if arr, ok := v.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, x := range arr {
			s, err := scalar(x)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	s, err := scalar(v)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

// listFlag is a flag that may be given several times or as a comma list.
// A list from a later source (environment over file, command line over
// both) replaces the earlier one instead of adding to it.
type listFlag struct {
	vals    []string
	replace bool
}

func (l *listFlag) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(l.vals, ",")
}

func (l *listFlag) Set(v string) error {
	if l.replace {
		l.vals, l.replace = nil, false
	}
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			l.vals = append(l.vals, s)
		}
	}
	return nil
}

// markListsReplaceable makes the next Set of every list flag start over.
func markListsReplaceable(fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		if l, ok := f.Value.(*listFlag); ok {
			l.replace = true
		}
	})
}

// parseFlagsWithEnv applies the configuration file and the environment
// to fs before parsing args, which win over both.
func parseFlagsWithEnv(fs *flag.FlagSet, args []string, allowed []string) error {
	if fs.Lookup("config") == nil {
		fs.String("config", "", "JSON yapılandırma dosyası; anahtarlar bayrak adları (ör. {\"listen-port\": 41641}); OPENSCALE_<BAYRAK> ortam değişkenleri de okunur")
	}
	path, ok, err := configFlagFrom(args)
	if err != nil {
		return err
	}
	if !ok {
		if v, set := lookupEnv(envConfigFile); set && v != "" {
			path, ok = v, true
		}
	}
	if ok {
		vals, err := configValues(path, allowed)
		if err != nil {
			return err
		}
		for _, name := range allowed {
			for _, v := range vals[name] {
				f := fs.Lookup(name)
				if f == nil {
					return fmt.Errorf("yapılandırma alanı %q bu komutta yok", name)
				}
				if err := f.Value.Set(v); err != nil {
					return usageError("yapılandırma alanı %q: %v", name, err)
				}
			}
		}
	}
	markListsReplaceable(fs)
	for _, name := range allowed {
		v, set := lookupEnv(EnvName(name))
		if !set {
			continue
		}
		if fs.Lookup(name) == nil {
			continue
		}
		if err := fs.Set(name, v); err != nil {
			return usageError("%s: %v", EnvName(name), err)
		}
	}
	markListsReplaceable(fs)
	return parseFlags(fs, args)
}
