package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// ConfigFile is the default configuration file name. It holds access
// tokens, so it is written and read as a private file.
const ConfigFile = "notify.json"

const (
	configSchema  = 1
	maxConfigFile = 64 << 10
	maxLabel      = 40
)

// Channel kinds of the configuration.
const (
	KindDesktop = "desktop"
	KindNtfy    = "ntfy"
	KindGotify  = "gotify"
	KindMatrix  = "matrix"
	KindSMTP    = "smtp"
)

// ChannelConfig is one configured channel. Only the fields of its kind
// are used.
type ChannelConfig struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// MinPriority and MaxPerHour bound deliveries.
	MinPriority string `json:"min_priority,omitempty"`
	MaxPerHour  int    `json:"max_per_hour,omitempty"`
	// URL is the ntfy topic URL, the Gotify server or the Matrix
	// homeserver.
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`
	Room  string `json:"room,omitempty"`
	// Devices are the owner's devices for desktop notifications.
	Devices []string `json:"devices,omitempty"`
	// SMTP fields. Password may stay empty when the caller reads it from
	// the operating system's credential store.
	SMTPAddr string   `json:"smtp_addr,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
}

// Config is the notification configuration.
type Config struct {
	Schema   int             `json:"schema"`
	Channels []ChannelConfig `json:"channels"`
	// QuietStart and QuietEnd are "HH:MM" in TimeZone (an IANA name;
	// empty means the computer's local time). Equal values disable quiet
	// hours.
	QuietStart string `json:"quiet_start,omitempty"`
	QuietEnd   string `json:"quiet_end,omitempty"`
	TimeZone   string `json:"time_zone,omitempty"`
	// DedupeMinutes is the repeat-suppression window (0 = default).
	DedupeMinutes int `json:"dedupe_minutes,omitempty"`
	// WeeklyReport turns on the weekly network report; ReportDay is the
	// weekday (0 = Sunday) and ReportHour the local hour it is sent.
	WeeklyReport bool `json:"weekly_report,omitempty"`
	ReportDay    int  `json:"report_day,omitempty"`
	ReportHour   int  `json:"report_hour,omitempty"`
}

// Validate checks the configuration without building channels.
func (c Config) Validate() error {
	if c.Schema != configSchema {
		return fmt.Errorf("bildirim yapılandırması sürümü %d desteklenmiyor", c.Schema)
	}
	if len(c.Channels) > maxRoutes {
		return fmt.Errorf("en fazla %d bildirim kanalı olabilir", maxRoutes)
	}
	seen := map[string]bool{}
	for _, ch := range c.Channels {
		l := strings.TrimSpace(ch.Label)
		if l == "" || len(l) > maxLabel || cleanLine(l) != l {
			return fmt.Errorf("kanal adı 1-%d karakter olmalı: %q", maxLabel, ch.Label)
		}
		if seen[l] {
			return fmt.Errorf("kanal adı iki kez kullanılmış: %q", l)
		}
		seen[l] = true
		if _, err := ParsePriority(ch.MinPriority); err != nil {
			return err
		}
		if ch.MaxPerHour < 0 || ch.MaxPerHour > 600 {
			return errors.New("saatlik sınır 0-600 olmalı")
		}
	}
	if _, err := c.quiet(); err != nil {
		return err
	}
	if c.DedupeMinutes < 0 || c.DedupeMinutes > 7*24*60 {
		return errors.New("tekrar bastırma süresi 0 ile 7 gün arasında olmalı")
	}
	if c.ReportDay < 0 || c.ReportDay > 6 || c.ReportHour < 0 || c.ReportHour > 23 {
		return errors.New("rapor günü 0-6, saati 0-23 olmalı")
	}
	return nil
}

func (c Config) location() (*time.Location, error) {
	if c.TimeZone == "" {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(c.TimeZone)
	if err != nil {
		return nil, fmt.Errorf("saat dilimi bilinmiyor: %q", c.TimeZone)
	}
	return loc, nil
}

func (c Config) quiet() (*QuietHours, error) {
	if c.QuietStart == "" && c.QuietEnd == "" {
		return nil, nil
	}
	s, err := ParseClock(c.QuietStart)
	if err != nil {
		return nil, err
	}
	e, err := ParseClock(c.QuietEnd)
	if err != nil {
		return nil, err
	}
	loc, err := c.location()
	if err != nil {
		return nil, err
	}
	return &QuietHours{Start: s, End: e, Location: loc}, nil
}

// ReportDue reports whether the weekly report should be sent at now, given
// the time the last one was sent.
func (c Config) ReportDue(now, last time.Time) bool {
	if !c.WeeklyReport {
		return false
	}
	loc, err := c.location()
	if err != nil {
		return false
	}
	lt := now.In(loc)
	if int(lt.Weekday()) != c.ReportDay || lt.Hour() < c.ReportHour {
		return false
	}
	return last.IsZero() || now.Sub(last) > 24*time.Hour
}

// Build creates the dispatcher. deliver carries desktop notifications to
// the owner's devices; it may be nil when no desktop channel is configured.
func (c Config) Build(deliver func(ctx context.Context, device string, m Message) error) (*Dispatcher, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	routes := make([]Route, 0, len(c.Channels))
	for _, ch := range c.Channels {
		var channel Channel
		var err error
		switch ch.Kind {
		case KindDesktop:
			if deliver == nil {
				return nil, errors.New("masaüstü bildirimi bu süreçte kullanılamıyor")
			}
			channel = &Desktop{Label: ch.Label, Devices: append([]string(nil), ch.Devices...), Deliver: deliver}
		case KindNtfy:
			channel, err = NewNtfy(ch.Label, ch.URL, ch.Token)
		case KindGotify:
			channel, err = NewGotify(ch.Label, ch.URL, ch.Token)
		case KindMatrix:
			channel, err = NewMatrix(ch.Label, ch.URL, ch.Room, ch.Token)
		case KindSMTP:
			var s *SMTP
			s, err = NewSMTP(ch.Label, ch.SMTPAddr, ch.From, ch.To)
			if err == nil {
				s.Username, s.Password = ch.Username, ch.Password
				channel = s
			}
		default:
			return nil, fmt.Errorf("bilinmeyen kanal türü %q", ch.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ch.Label, err)
		}
		p, _ := ParsePriority(ch.MinPriority)
		routes = append(routes, Route{Channel: channel, MinPriority: p, MaxPerHour: ch.MaxPerHour})
	}
	q, _ := c.quiet()
	return NewDispatcher(routes, DispatcherOptions{DedupeWindow: time.Duration(c.DedupeMinutes) * time.Minute, Quiet: q})
}

// Redacted returns a copy without tokens and passwords, for the panel.
func (c Config) Redacted() Config {
	out := c
	out.Channels = make([]ChannelConfig, len(c.Channels))
	for i, ch := range c.Channels {
		if ch.Token != "" {
			ch.Token = "***"
		}
		if ch.Password != "" {
			ch.Password = "***"
		}
		out.Channels[i] = ch
	}
	return out
}

// Load reads a configuration written by Save.
func Load(path string) (Config, error) {
	data, err := securefile.ReadPrivate(path, maxConfigFile)
	if err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("bildirim yapılandırması okunamadı: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Save writes c as a private file.
func Save(path string, c Config) error {
	if c.Schema == 0 {
		c.Schema = configSchema
	}
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(path, append(data, '\n'))
}
