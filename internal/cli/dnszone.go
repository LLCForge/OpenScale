package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// MagicDNS zone commands (ADR-0034, F-053, F-054, F-055, #39, #97).

const zoneCompatNote = "Not: eski sürümlü cihazlar magic_dns bölümü veya cihaz takma adı olan belgeyi reddeder; önce bütün cihazları güncelle."

// editZone applies edit to a copy of the magic_dns section; a section
// left empty is removed.
func editZone(doc *trust.Document, edit func(s *trust.MagicDNSSettings) error) error {
	s := &trust.MagicDNSSettings{}
	if doc.MagicDNS != nil {
		s.Search = slices.Clone(doc.MagicDNS.Search)
		s.Records = slices.Clone(doc.MagicDNS.Records)
		s.DeviceSubdomains = doc.MagicDNS.DeviceSubdomains
	}
	if err := edit(s); err != nil {
		return err
	}
	if len(s.Search) == 0 && len(s.Records) == 0 && !s.DeviceSubdomains {
		return doc.SetMagicDNS(nil)
	}
	return doc.SetMagicDNS(s)
}

func cmdNetworkDNSSearch(env *Env, args []string) error {
	fs := newFlagSet(env, "network dns search")
	common := addEditFlags(fs)
	domains := fs.String("domains", "", "kısa adlara eklenecek alanlar, virgülle: ağ alanı veya split DNS alanları (boş: kaldır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	list := splitList(strings.ToLower(*domains))
	fmt.Fprintln(env.Stdout, zoneCompatNote)
	return runEdit(env, common, func(doc *trust.Document) error {
		return editZone(doc, func(s *trust.MagicDNSSettings) error {
			s.Search = list
			return nil
		})
	})
}

func cmdNetworkDNSSubdomains(env *Env, args []string) error {
	fs := newFlagSet(env, "network dns subdomains")
	common := addEditFlags(fs)
	state := fs.String("state", "", "on: x.cihaz.alan cihaza çözülür; off: kapalı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var on bool
	switch *state {
	case "on":
		on = true
	case "off":
	default:
		return usageError("kullanım: openscale network dns subdomains --state on|off --dir KLASÖR")
	}
	fmt.Fprintln(env.Stdout, zoneCompatNote)
	return runEdit(env, common, func(doc *trust.Document) error {
		return editZone(doc, func(s *trust.MagicDNSSettings) error {
			s.DeviceSubdomains = on
			return nil
		})
	})
}

type recordFlags struct {
	name, typ, value       *string
	priority, weight, port *int
}

func addRecordFlags(env *Env, name string) (*recordFlags, editFlags, func([]string) error) {
	fs := newFlagSet(env, name)
	common := addEditFlags(fs)
	f := &recordFlags{
		name:     fs.String("name", "", "ağ alanına göre ad: nas, _rdp._tcp.masaustu, *.lab"),
		typ:      fs.String("type", "", "kayıt türü: A, AAAA, CNAME, SRV, TXT"),
		value:    fs.String("value", "", "adres (A/AAAA), hedef ad (CNAME/SRV, sonda nokta olmadan) veya metin (TXT)"),
		priority: fs.Int("priority", 0, "SRV önceliği"),
		weight:   fs.Int("weight", 0, "SRV ağırlığı"),
		port:     fs.Int("port", 0, "SRV portu"),
	}
	return f, common, func(args []string) error { return parseFlags(fs, args) }
}

func (f *recordFlags) record() (trust.DNSRecord, error) {
	for _, v := range []*int{f.priority, f.weight, f.port} {
		if *v < 0 || *v > 65535 {
			return trust.DNSRecord{}, usageError("--priority, --weight ve --port 0-65535 olmalı")
		}
	}
	r := trust.DNSRecord{
		Name:     strings.ToLower(strings.TrimSpace(*f.name)),
		Type:     strings.ToUpper(strings.TrimSpace(*f.typ)),
		Value:    strings.TrimSpace(*f.value),
		Priority: uint16(*f.priority), //nolint:gosec // checked above
		Weight:   uint16(*f.weight),   //nolint:gosec // checked above
		Port:     uint16(*f.port),     //nolint:gosec // checked above
	}
	if r.Type == trust.RecordCNAME || r.Type == trust.RecordSRV {
		r.Value = strings.TrimSuffix(strings.ToLower(r.Value), ".")
	}
	if r.Name == "" || r.Type == "" || r.Value == "" {
		return trust.DNSRecord{}, usageError("--name, --type ve --value zorunlu")
	}
	return r, nil
}

func cmdNetworkDNSRecordAdd(env *Env, args []string) error {
	f, common, parse := addRecordFlags(env, "network dns record add")
	if err := parse(args); err != nil {
		return err
	}
	r, err := f.record()
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, zoneCompatNote)
	return runEdit(env, common, func(doc *trust.Document) error {
		return editZone(doc, func(s *trust.MagicDNSSettings) error {
			s.Records = append(s.Records, r)
			return nil
		})
	})
}

func cmdNetworkDNSRecordRemove(env *Env, args []string) error {
	f, common, parse := addRecordFlags(env, "network dns record rm")
	if err := parse(args); err != nil {
		return err
	}
	name, typ, value := strings.ToLower(strings.TrimSpace(*f.name)), strings.ToUpper(strings.TrimSpace(*f.typ)), strings.TrimSpace(*f.value)
	if name == "" {
		return usageError("--name zorunlu (--type ve --value isteğe bağlı süzgeçtir)")
	}
	return runEdit(env, common, func(doc *trust.Document) error {
		return editZone(doc, func(s *trust.MagicDNSSettings) error {
			before := len(s.Records)
			s.Records = slices.DeleteFunc(s.Records, func(r trust.DNSRecord) bool {
				return r.Name == name && (typ == "" || r.Type == typ) && (value == "" || r.Value == value)
			})
			if len(s.Records) == before {
				return fmt.Errorf("%s adında eşleşen kayıt yok", name)
			}
			return nil
		})
	})
}

func cmdDeviceAlias(env *Env, args []string) error {
	fs := newFlagSet(env, "device alias")
	common := addEditFlags(fs)
	device := fs.String("name", "", "cihaz adı")
	aliases := fs.String("aliases", "", "cihazın ek MagicDNS adları, virgülle (boş: kaldır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *device == "" {
		return usageError("--name zorunlu")
	}
	list := splitList(strings.ToLower(*aliases))
	fmt.Fprintln(env.Stdout, zoneCompatNote)
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetDeviceAliases(*device, list) })
}

// printZone shows the magic_dns section and the device aliases.
func printZone(env *Env, doc *trust.Document) {
	w := env.Stdout
	for _, d := range doc.Devices {
		if len(d.Aliases) > 0 {
			fmt.Fprintf(w, "Takma adlar: %s => %s\n", d.Name, strings.Join(d.Aliases, ", "))
		}
	}
	s := doc.MagicDNS
	if s == nil {
		return
	}
	if len(s.Search) > 0 {
		fmt.Fprintf(w, "Arama alanları: %s\n", strings.Join(s.Search, ", "))
	}
	if s.DeviceSubdomains {
		fmt.Fprintf(w, "Cihaz alt alanları açık: *.cihaz.%s cihaza çözülür\n", doc.DNSDomain)
	}
	for _, r := range s.Records {
		value := r.Value
		if r.Type == trust.RecordSRV {
			value = strconv.Itoa(int(r.Priority)) + " " + strconv.Itoa(int(r.Weight)) + " " + strconv.Itoa(int(r.Port)) + " " + r.Value
		}
		fmt.Fprintf(w, "  %s.%s %s %s\n", r.Name, doc.DNSDomain, r.Type, value)
	}
}
