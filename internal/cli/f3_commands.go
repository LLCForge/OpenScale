package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/openscale/openscale/internal/winapp"
)

// Phase 3 desktop commands (#802, #803).
//
//	openscale send-to <file>...         Explorer's "Send to > OpenScale"
//	openscale tray left-click <choice>  what a left click on the tray icon does

func init() {
	registerCommands(
		command{"send-to", "Dosyaları tepsideki alıcı seçiciyle uçtan uca gönderir (Gezgin > Gönder > OpenScale): <dosya>...", cmdSendTo},
		command{"tray left-click", "Tepsi simgesine sol tıklayınca ne açılacağı: flyout (durum penceresi, varsayılan) veya panel", cmdTrayLeftClick},
	)
}

// sendToMessage explains a refused Send to request in the display
// language.
func sendToMessage(err error) string {
	var ae *winapp.SendToArgError
	switch {
	case errors.Is(err, winapp.ErrSendToNone):
		return winapp.Tr("Gönderilecek dosya seçilmedi.", "No file was chosen to send.")
	case errors.Is(err, winapp.ErrSendToTooMany):
		return winapp.Tr(fmt.Sprintf("En çok %d dosya birlikte gönderilebilir.", winapp.MaxSendToFiles),
			fmt.Sprintf("At most %d files can be sent together.", winapp.MaxSendToFiles))
	case errors.Is(err, winapp.ErrSendToTooLarge):
		return winapp.Tr("Dosyalar çok büyük (dosya başına en çok 2 GiB, toplam 8 GiB).", "The files are too large (at most 2 GiB each, 8 GiB in total).")
	case errors.As(err, &ae):
		return winapp.Tr("Bu dosya gönderilemiyor: ", "This file cannot be sent: ") + ae.Path + "\n\n" +
			winapp.Tr("Yalnızca normal dosyalar gönderilebilir; klasörler, kısayollar ve aygıtlar gönderilemez.",
				"Only normal files can be sent; folders, shortcuts and devices cannot.")
	case errors.Is(err, winapp.ErrSendToTrayMissing):
		return winapp.Tr("OpenScale tepsi uygulaması çalışmıyor. OpenScale'i açıp yeniden deneyin.",
			"The OpenScale tray app is not running. Open OpenScale and try again.")
	}
	return winapp.Tr("Dosyalar OpenScale'e iletilemedi: ", "The files could not be handed to OpenScale: ") + err.Error()
}

func cmdSendTo(env *Env, args []string) error {
	// Explorer passes the chosen files as they are; none of them is a
	// flag, so "--" and leading dashes are not interpreted.
	paths := args
	if len(paths) > 0 && paths[0] == "--" {
		paths = paths[1:]
	}
	// Started from Explorer, the console window would only flash.
	gui := winapp.DetachOwnConsole()
	fail := func(err error) error {
		msg := sendToMessage(err)
		if gui {
			winapp.ShowMessage(msg, true)
		}
		return errors.New(msg)
	}
	infos, err := winapp.CheckSendToArgs(paths, os.Lstat)
	if err != nil {
		return fail(err)
	}
	clean := make([]string, 0, len(infos))
	for _, in := range infos {
		clean = append(clean, in.Path)
	}
	if err := winapp.SendToTray(clean); err != nil {
		return fail(err)
	}
	if !gui {
		fmt.Fprintln(env.Stdout, winapp.Tr("Dosyalar tepsiye iletildi; alıcıyı açılan pencereden seçin.", "The files were handed to the tray; choose the recipient in the window that opens."))
	}
	return nil
}

func cmdTrayLeftClick(env *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.Stdout, winapp.TrayLeftClick())
		return nil
	}
	if len(args) != 1 {
		return usageError("kullanım: openscale tray left-click [flyout|panel]")
	}
	choice := strings.ToLower(strings.TrimSpace(args[0]))
	if choice != winapp.LeftClickFlyout && choice != winapp.LeftClickPanel {
		return usageError("seçim flyout veya panel olmalı")
	}
	if err := winapp.SetTrayLeftClick(choice); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, winapp.Tr("Kaydedildi; tepsi bir sonraki tıklamada bunu kullanır.", "Saved; the tray uses it on the next click."))
	return nil
}
