package leaktest

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/geoip"
)

// Location consistency (#404): the operating system's time zone and
// language region are compared with the country of the address sites see
// (the exit node's, from the bundled table). A mismatch is information
// only: sites may notice it, but nothing is changed automatically and no
// outside service is asked.

// CheckLocation is the location consistency check.
const CheckLocation = "location"

// Locale is what this device tells sites about where it is.
type Locale struct {
	// TimeZone is an IANA name ("Europe/Istanbul") or a Windows zone key
	// ("Turkey Standard Time"); "" when unknown.
	TimeZone string
	// Region is the ISO 3166-1 alpha-2 region of the language setting
	// ("TR" from tr_TR.UTF-8); "" when unknown.
	Region string
}

// AddLocation appends the location check to a finished report. It adds
// nothing when the seen address has no known country or the locale is
// unknown, and it never marks a leak.
func AddLocation(rep *Report, loc Locale) {
	if c, ok := locationCheck(rep, loc); ok {
		rep.add(c)
	}
}

func locationCheck(rep *Report, loc Locale) (Check, bool) {
	exit := ""
	for _, s := range []string{rep.SeenIPv4, rep.SeenIPv6} {
		if a, err := netip.ParseAddr(s); err == nil {
			if exit = geoip.Country(a); exit != "" {
				break
			}
		}
	}
	tzc := zoneCountry(loc.TimeZone)
	region := strings.ToUpper(loc.Region)
	if exit == "" || (tzc == "" && region == "") {
		return Check{}, false
	}
	var parts, odd []string
	if tzc != "" {
		parts = append(parts, fmt.Sprintf("saat dilimi %s (%s)", loc.TimeZone, tzc))
		if tzc != exit {
			odd = append(odd, "saat dilimi")
		}
	}
	if region != "" {
		parts = append(parts, "dil bölgesi "+region)
		if region != exit {
			odd = append(odd, "dil bölgesi")
		}
	}
	detail := fmt.Sprintf("Sitelerin gördüğü ülke %s; bu cihazda %s.", exit, strings.Join(parts, ", "))
	c := Check{ID: CheckLocation, Level: LevelOK, Title: "Konum tutarlılığı", Detail: detail}
	if len(odd) > 0 {
		c.Level = LevelInfo
		c.Detail += " Uyumsuz: " + strings.Join(odd, ", ") + ". Siteler bunu fark edebilir; hiçbir ayar değiştirilmedi."
	}
	return c, true
}

// LocalLocale reads this device's time zone and language region.
func LocalLocale() Locale {
	return Locale{TimeZone: localTimeZone(), Region: langRegion()}
}

// localTimeZone: TZ, then the /etc/localtime link, then the platform's own
// setting (Windows registry).
func localTimeZone() string {
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" && zoneCountry(tz) != "" {
		return tz
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		target = filepath.ToSlash(target)
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return target[i+len("zoneinfo/"):]
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil && len(b) < 128 {
		return strings.TrimSpace(string(b))
	}
	return platformTimeZone()
}

// langRegion returns the region of LC_ALL, LC_MESSAGES or LANG.
func langRegion() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if r := regionOf(os.Getenv(k)); r != "" {
			return r
		}
	}
	return platformRegion()
}

// regionOf parses "tr_TR.UTF-8", "en-GB" or "de_DE@euro".
func regionOf(s string) string {
	s, _, _ = strings.Cut(s, ".")
	s, _, _ = strings.Cut(s, "@")
	i := strings.IndexAny(s, "_-")
	if i < 0 {
		return ""
	}
	r := strings.ToUpper(s[i+1:])
	if len(r) != 2 || r[0] < 'A' || r[0] > 'Z' || r[1] < 'A' || r[1] > 'Z' {
		return ""
	}
	return r
}

// zoneCountry maps a zone name to its country; "" when unknown or when the
// zone is not tied to one country (UTC).
func zoneCountry(tz string) string {
	if c, ok := ianaZones[tz]; ok {
		return c
	}
	return windowsZones[tz]
}

// ianaZones covers the common zones; others are simply not compared.
var ianaZones = map[string]string{
	"Europe/Istanbul": "TR", "Asia/Istanbul": "TR", "Turkey": "TR",
	"Europe/London": "GB", "Europe/Dublin": "IE", "Europe/Lisbon": "PT", "Europe/Madrid": "ES",
	"Europe/Paris": "FR", "Europe/Brussels": "BE", "Europe/Amsterdam": "NL", "Europe/Luxembourg": "LU",
	"Europe/Berlin": "DE", "Europe/Zurich": "CH", "Europe/Vienna": "AT", "Europe/Rome": "IT",
	"Europe/Prague": "CZ", "Europe/Warsaw": "PL", "Europe/Budapest": "HU", "Europe/Bratislava": "SK",
	"Europe/Ljubljana": "SI", "Europe/Zagreb": "HR", "Europe/Belgrade": "RS", "Europe/Sarajevo": "BA",
	"Europe/Skopje": "MK", "Europe/Tirane": "AL", "Europe/Athens": "GR", "Europe/Sofia": "BG",
	"Europe/Bucharest": "RO", "Europe/Chisinau": "MD", "Europe/Kiev": "UA", "Europe/Kyiv": "UA",
	"Europe/Minsk": "BY", "Europe/Moscow": "RU", "Europe/Vilnius": "LT", "Europe/Riga": "LV",
	"Europe/Tallinn": "EE", "Europe/Helsinki": "FI", "Europe/Stockholm": "SE", "Europe/Oslo": "NO",
	"Europe/Copenhagen": "DK", "Atlantic/Reykjavik": "IS", "Asia/Nicosia": "CY", "Europe/Nicosia": "CY",
	"Europe/Malta": "MT", "Europe/Monaco": "MC", "Europe/Andorra": "AD",
	"Asia/Baku": "AZ", "Asia/Tbilisi": "GE", "Asia/Yerevan": "AM", "Asia/Tehran": "IR",
	"Asia/Baghdad": "IQ", "Asia/Jerusalem": "IL", "Asia/Tel_Aviv": "IL", "Asia/Beirut": "LB",
	"Asia/Damascus": "SY", "Asia/Amman": "JO", "Asia/Riyadh": "SA", "Asia/Dubai": "AE",
	"Asia/Qatar": "QA", "Asia/Kuwait": "KW", "Asia/Bahrain": "BH", "Asia/Muscat": "OM",
	"Asia/Karachi": "PK", "Asia/Kolkata": "IN", "Asia/Calcutta": "IN", "Asia/Dhaka": "BD",
	"Asia/Kathmandu": "NP", "Asia/Colombo": "LK", "Asia/Tashkent": "UZ", "Asia/Almaty": "KZ",
	"Asia/Bishkek": "KG", "Asia/Bangkok": "TH", "Asia/Ho_Chi_Minh": "VN", "Asia/Jakarta": "ID",
	"Asia/Kuala_Lumpur": "MY", "Asia/Singapore": "SG", "Asia/Manila": "PH", "Asia/Shanghai": "CN",
	"Asia/Hong_Kong": "HK", "Asia/Taipei": "TW", "Asia/Seoul": "KR", "Asia/Tokyo": "JP",
	"Australia/Sydney": "AU", "Australia/Melbourne": "AU", "Australia/Brisbane": "AU", "Australia/Perth": "AU",
	"Australia/Adelaide": "AU", "Pacific/Auckland": "NZ",
	"Africa/Cairo": "EG", "Africa/Casablanca": "MA", "Africa/Algiers": "DZ", "Africa/Tunis": "TN",
	"Africa/Lagos": "NG", "Africa/Nairobi": "KE", "Africa/Johannesburg": "ZA",
	"America/New_York": "US", "America/Chicago": "US", "America/Denver": "US", "America/Phoenix": "US",
	"America/Los_Angeles": "US", "America/Anchorage": "US", "Pacific/Honolulu": "US", "America/Detroit": "US",
	"America/Toronto": "CA", "America/Vancouver": "CA", "America/Edmonton": "CA", "America/Winnipeg": "CA",
	"America/Halifax": "CA", "America/Montreal": "CA", "America/Mexico_City": "MX", "America/Bogota": "CO",
	"America/Lima": "PE", "America/Santiago": "CL", "America/Argentina/Buenos_Aires": "AR",
	"America/Buenos_Aires": "AR", "America/Sao_Paulo": "BR", "America/Caracas": "VE",
}

// windowsZones are Windows time zone keys used by a single country only;
// shared keys ("W. Europe Standard Time") are not compared.
var windowsZones = map[string]string{
	"Turkey Standard Time": "TR", "Russian Standard Time": "RU", "Belarus Standard Time": "BY",
	"Azerbaijan Standard Time": "AZ", "Georgian Standard Time": "GE", "Caucasus Standard Time": "AM",
	"Iran Standard Time": "IR", "Israel Standard Time": "IL", "Jordan Standard Time": "JO",
	"Pakistan Standard Time": "PK", "India Standard Time": "IN", "Singapore Standard Time": "SG",
	"Taipei Standard Time": "TW", "Korea Standard Time": "KR", "Tokyo Standard Time": "JP",
	"New Zealand Standard Time": "NZ", "Egypt Standard Time": "EG", "Morocco Standard Time": "MA",
	"AUS Eastern Standard Time": "AU", "E. South America Standard Time": "BR", "Argentina Standard Time": "AR",
	"Canada Central Standard Time": "CA",
}
