package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/openscale/openscale/internal/panel"
)

// Network locations (ADR-0226): the owner's switch for adding the other
// devices' SMB shares under "Ağdaki konumlar" in Windows Explorer. The
// switch lives in the desktop service; the tray makes the locations.

func init() {
	registerCommands(
		command{"netdrive auto on", "Cihazların SMB paylaşımlarını Windows Gezgini'nde 'Ağdaki konumlar' altına kendiliğinden ekler (varsayılan açık; ADR-0226)", cmdNetdriveAutoOn},
		command{"netdrive auto off", "OpenScale'in eklediği ağ konumlarını kaldırır ve yenilerini eklemez; elle eklenenlere dokunmaz", cmdNetdriveAutoOff},
		command{"netdrive auto status", "Ağ konumu anahtarını ve cihazların bildirdiği paylaşımları gösterir: [--json]", cmdNetdriveAutoStatus},
	)
}

func cmdNetdriveAutoOn(env *Env, args []string) error { return netdriveAutoSet(env, args, true) }

func cmdNetdriveAutoOff(env *Env, args []string) error { return netdriveAutoSet(env, args, false) }

func netdriveAutoSet(env *Env, args []string, on bool) error {
	fs := newFlagSet(env, "netdrive auto")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := netdriveAutoClient(env)
	if err != nil {
		return err
	}
	var st panel.NetPlacesStatus
	if err := c.post(env, "/netplaces", panel.NetPlacesRequest{On: on}, &st); err != nil {
		return netdriveAutoError(err)
	}
	if on {
		fmt.Fprintln(env.Stdout, "Ağ konumları açık: tepsi simgesi bir dakika içinde paylaşımları 'Ağdaki konumlar' altına ekler.")
	} else {
		fmt.Fprintln(env.Stdout, "Ağ konumları kapalı: tepsi simgesi OpenScale'in eklediği konumları bir dakika içinde kaldırır.")
	}
	printNetPlacesNotes(env, st)
	return nil
}

func cmdNetdriveAutoStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "netdrive auto status")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := netdriveAutoClient(env)
	if err != nil {
		return err
	}
	var st panel.NetPlacesStatus
	if err := c.get(env, "/netplaces", &st); err != nil {
		return netdriveAutoError(err)
	}
	if *asJSON {
		if st.Devices == nil {
			st.Devices = []panel.NetPlaceDevice{}
		}
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	state := "kapalı"
	if st.On {
		state = "açık"
	}
	fmt.Fprintf(env.Stdout, "Ağ konumları: %s\n", state)
	printNetPlacesNotes(env, st)
	for _, d := range st.Devices {
		switch {
		case !d.Known:
			fmt.Fprintf(env.Stdout, "  %-24s rapor yok\n", d.Name)
		case len(d.Shares) == 0:
			fmt.Fprintf(env.Stdout, "  %-24s paylaşım yok\n", d.Name)
		default:
			for _, s := range d.Shares {
				fmt.Fprintf(env.Stdout, "  %-24s \\\\%s\\%s\n", d.Name, d.Host, s.Name)
			}
		}
	}
	return nil
}

func printNetPlacesNotes(env *Env, st panel.NetPlacesStatus) {
	switch {
	case !st.Supported:
		fmt.Fprintln(env.Stdout, "Not: ağ konumları yalnızca Windows'ta, tepsi simgesi çalışırken eklenir.")
	case !st.Admin:
		fmt.Fprintln(env.Stdout, "Not: bu cihaz yönetici değil; diğer cihazların paylaşım listesi yalnızca yönetici cihazlara gelir.")
	case !st.Ready:
		fmt.Fprintln(env.Stdout, "Not: tünel çalışmıyor; konumlar tünel açılınca güncellenir.")
	}
}

func netdriveAutoClient(env *Env) (*localClient, error) {
	c, err := openLocalClient(env, "")
	if err != nil {
		return nil, err
	}
	if !c.service {
		return nil, errors.New("ağ konumları yalnızca Windows masaüstü servisinde var")
	}
	return c, nil
}

func netdriveAutoError(err error) error {
	var ae *apiError
	if errors.As(err, &ae) && ae.status == http.StatusNotFound {
		return errors.New("bu OpenScale servisi ağ konumlarını bilmiyor; servisi güncelleyin")
	}
	return err
}
