package cli

import (
	"context"
	"errors"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/mqttpub"
	"github.com/openscale/openscale/internal/panel"
)

// The MQTT publisher (#561, ADR-0167): like the webhook forwarder it reads
// the documented local API and runs only when the owner starts it.

// mqttStatusEvery is how often the retained status is refreshed.
const mqttStatusEvery = time.Minute

func mqttPath(env *Env, config string) (string, error) {
	if config != "" {
		return config, nil
	}
	if d := localAPI.dataDir(); d != "" {
		return filepath.Join(d, mqttpub.ConfigFile), nil
	}
	dir, err := resolveStateDir(env, "")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, mqttpub.ConfigFile), nil
}

func cmdMQTT(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("bir alt komut yazın: init --broker <ana-makine:port> [--prefix openscale] [--user ad --password-file dosya] [--events a,b] | show | test | run | off")
	}
	sub := args[0]
	fs := newFlagSet(env, "mqtt "+sub)
	config := fs.String("config", "", "yapılandırma dosyası")
	broker := fs.String("broker", "", "MQTT aracısı, ana-makine:port (yalnızca loopback veya özel ağ; port verilmezse 1883)")
	prefix := fs.String("prefix", mqttpub.DefaultPrefix, "konu öneki")
	user := fs.String("user", "", "aracı kullanıcı adı")
	passwordFile := fs.String("password-file", "", "aracı parolasını içeren dosya (parola komut satırına yazılmaz)")
	events := fs.String("events", "", "yayımlanacak olay türleri veya kategorileri, virgülle (boş: hepsi)")
	stateDir := fs.String("state-dir", "", "'openscale up' durum klasörü (run, test)")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	path, err := mqttPath(env, *config)
	if err != nil {
		return err
	}
	w := env.Stdout
	switch sub {
	case "init":
		password := ""
		if *passwordFile != "" {
			data, err := os.ReadFile(*passwordFile)
			if err != nil {
				return fmt.Errorf("parola dosyası okunamadı: %w", err)
			}
			password = strings.TrimRight(string(data), "\r\n")
		}
		var kinds []string
		for _, k := range strings.Split(*events, ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, k)
			}
		}
		c, err := mqttpub.NewConfig(strings.TrimSpace(*broker), *prefix, *user, password, kinds, env.Random)
		if err != nil {
			return err
		}
		if err := mqttpub.Save(path, c); err != nil {
			return err
		}
		fmt.Fprintf(w, "MQTT yapılandırması yazıldı: %s\nKonular: %s/<cihaz>/availability, /status, /event\n", path, c.Prefix)
		fmt.Fprintln(w, "Yayını başlatmak için: openscale mqtt run   (deneme: openscale mqtt test)")
		if password != "" && !strings.HasPrefix(c.Broker, "127.") && !strings.HasPrefix(c.Broker, "[::1]") && !strings.HasPrefix(c.Broker, "localhost") {
			fmt.Fprintln(w, "Uyarı: MQTT 3.1.1 parolayı düz metin gönderir. Aracı başka bir bilgisayardaysa ona OpenScale tüneli içinden (100.64/10 adresi) bağlanın.")
		}
		return nil
	case "show":
		c, err := mqttpub.Load(path)
		if err != nil {
			return err
		}
		if c.Password != "" {
			c.Password = "(gizli)"
		}
		return printJSON(w, c)
	case "off":
		if err := os.Remove(path); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			return err
		}
		fmt.Fprintln(w, "MQTT yapılandırması silindi; çalışan yayıncı durdurulmalı.")
		return nil
	case "test":
		c, err := mqttpub.Load(path)
		if err != nil {
			return err
		}
		device := mqttDevice(env, *stateDir)
		ctx, cancel := context.WithTimeout(envContext(env), 2*mqttpub.Timeout)
		defer cancel()
		cl, err := mqttpub.Connect(ctx, c, device, env.Now)
		if err != nil {
			return err
		}
		defer cl.Close()
		ev, _ := mqttpub.Event{Device: device, At: env.Now().UTC(), Kind: "mqtt_test", Category: "test", Severity: "info", Message: "OpenScale MQTT denemesi"}.Encode()
		if err := cl.Publish(mqttpub.TopicsFor(c, device).Event, ev, false); err != nil {
			return err
		}
		fmt.Fprintf(w, "Deneme iletisi yayımlandı: %s\n", mqttpub.TopicsFor(c, device).Event)
		return nil
	case "run":
		return runMQTT(env, path, *stateDir)
	}
	return usageError("bilinmeyen alt komut %q", sub)
}

// mqttDevice is this device's name, or "cihaz" without a tunnel.
func mqttDevice(env *Env, stateDir string) string {
	lc, err := openLocalClient(env, stateDir)
	if err != nil {
		return "cihaz"
	}
	var st panel.DiagStatus
	if lc.get(env, "/status", &st) == nil && st.Self != nil && st.Self.Name != "" {
		return st.Self.Name
	}
	return "cihaz"
}

func statusMessage(device string, st panel.DiagStatus, now time.Time) mqttpub.Status {
	s := mqttpub.Status{Device: device, At: now.UTC(), Running: st.Running, Connected: st.Connected, Peers: len(st.Peers), ExitNode: st.ExitNode, Healthy: st.Running && st.LastSyncError == ""}
	for _, p := range st.Peers {
		if p.Online {
			s.PeersOnline++
		}
		if p.Path == panel.PathRelay {
			s.PeersRelay++
		}
	}
	return s
}

// runMQTT publishes until Ctrl+C, reconnecting with a growing pause.
func runMQTT(env *Env, path, stateDir string) error {
	c, err := mqttpub.Load(path)
	if err != nil {
		return err
	}
	lc, err := openLocalClient(env, stateDir)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	var st panel.DiagStatus
	device := "cihaz"
	if lc.get(env, "/status", &st) == nil && st.Self != nil {
		device = st.Self.Name
	}
	topics := mqttpub.TopicsFor(c, device)
	var rep panel.EventStreamReply
	if err := lc.get(env, "/events/poll?since=0&wait=0", &rep); err != nil {
		return err
	}
	since := rep.Next
	fmt.Fprintf(env.Stdout, "Durum ve olaylar %s aracısına yayımlanıyor (%s/...). Durdurmak için Ctrl+C.\n", c.Broker, strings.TrimSuffix(topics.Status, "/status"))
	failures := 0
	for ctx.Err() == nil {
		cl, err := mqttpub.Connect(ctx, c, device, env.Now)
		if err != nil {
			if errors.Is(err, mqttpub.ErrDestination) || errors.Is(err, mqttpub.ErrConfig) {
				return err
			}
			failures++
			fmt.Fprintf(env.Stderr, "uyarı: %v; yeniden denenecek\n", err)
			if !sleepCtx(ctx, time.Duration(min(failures, 6))*5*time.Second) {
				break
			}
			continue
		}
		failures = 0
		since, err = publishLoop(env, lc, cl, c, device, topics, since)
		if ctx.Err() != nil {
			_ = cl.Publish(topics.Availability, []byte("offline"), true)
			_ = cl.Close()
			break
		}
		_ = cl.Close()
		if err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: %v; yeniden bağlanılacak\n", err)
			if !sleepCtx(ctx, 5*time.Second) {
				break
			}
		}
	}
	return nil
}

// publishLoop publishes the status and the events over one connection
// until it fails or ctx ends; it returns the next event number.
func publishLoop(env *Env, lc *localClient, cl *mqttpub.Client, c *mqttpub.Config, device string, t mqttpub.Topics, since uint64) (uint64, error) {
	ctx := envContext(env)
	if err := cl.Publish(t.Availability, []byte("online"), true); err != nil {
		return since, err
	}
	lastStatus := time.Time{}
	for ctx.Err() == nil {
		if now := env.Now(); now.Sub(lastStatus) >= mqttStatusEvery {
			var st panel.DiagStatus
			if err := lc.get(env, "/status", &st); err == nil {
				payload, _ := statusMessage(device, st, now).Encode()
				if err := cl.Publish(t.Status, payload, true); err != nil {
					return since, err
				}
			}
			lastStatus = now
		}
		var batch panel.EventStreamReply
		err := lc.call(ctx, "GET", fmt.Sprintf("%s/events/poll?since=%d&wait=%d", panel.LocalAPIPrefix, since, webhookPollWait), nil, &batch)
		if err != nil {
			if ctx.Err() != nil {
				return since, nil
			}
			if !sleepCtx(ctx, 5*time.Second) {
				return since, nil
			}
			continue
		}
		for _, ev := range batch.Events {
			if !c.Wants(ev.Kind, ev.Category) {
				continue
			}
			payload, err := mqttpub.Event{Device: device, Seq: ev.Seq, At: ev.At, Kind: ev.Kind, Category: ev.Category, Severity: ev.Severity, Peer: ev.Peer, Message: ev.Message}.Encode()
			if err != nil {
				continue
			}
			if err := cl.Publish(t.Event, payload, false); err != nil {
				return since, err
			}
		}
		since = batch.Next
		if err := cl.Ping(); err != nil {
			return since, err
		}
	}
	return since, nil
}
