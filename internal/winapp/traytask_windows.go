//go:build windows

package winapp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The tray runs elevated (the app token is readable only by administrators),
// so starting it from the Run key asked for consent at every sign-in. A
// scheduled task with the highest available run level starts it elevated
// for administrators without asking. The Run entry stays for the autostart
// setting and for standard users; an unelevated start skips the elevation
// request when this task is installed (desktop.runAppMode).

const (
	trayTaskName       = `OpenScale\Tray`
	trayTaskStateValue = "TrayTaskInstalled"
	// usersGroupSID: every interactive user; administrators get their full
	// token through RunLevel HighestAvailable.
	usersGroupSID   = "S-1-5-32-545"
	schtasksTimeout = 30 * time.Second
	// taskSchemaNS names the Task Scheduler XML schema; nothing is fetched.
	taskSchemaNS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
)

func trayTaskXML(exe string) (string, error) {
	if !filepath.IsAbs(exe) {
		return "", errors.New("görev için program yolu mutlak olmalı")
	}
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="` + taskSchemaNS + `">
  <RegistrationInfo><Description>OpenScale tepsi simgesi (oturum açılışında)</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><GroupId>` + usersGroupSID + `</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + esc(exe) + `</Command><Arguments>autostart run</Arguments><WorkingDirectory>` + esc(filepath.Dir(exe)) + `</WorkingDirectory></Exec></Actions>
</Task>
`, nil
}

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2, 2+2*len(u))
	out[0], out[1] = 0xFF, 0xFE
	for _, c := range u {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

func runSchtasks(args ...string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), schtasksTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(sys, "schtasks.exe"), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// installTrayTask needs an elevated process. The task definition is written
// into the data folder, which only SYSTEM and administrators can change, so
// nobody can swap it between writing and registering.
func installTrayTask(exe string) error {
	def, err := trayTaskXML(exe)
	if err != nil {
		return err
	}
	tmp := filepath.Join(DataDir(), "tray-task.xml")
	if err := os.WriteFile(tmp, encodeUTF16LE(def), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := runSchtasks("/Create", "/TN", trayTaskName, "/XML", tmp, "/F"); err != nil {
		setTrayTaskState(false)
		return err
	}
	setTrayTaskState(true)
	return nil
}

func removeTrayTask() {
	_ = runSchtasks("/Delete", "/TN", trayTaskName, "/F")
	setTrayTaskState(false)
}

func setTrayTaskState(on bool) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, shortcutStateKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if on {
		_ = k.SetDWordValue(trayTaskStateValue, 1)
	} else {
		_ = k.DeleteValue(trayTaskStateValue)
	}
}

// TrayTaskInstalled reports whether the elevated sign-in task is in place.
// The value lives under HKLM, which standard users cannot write.
func TrayTaskInstalled() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, shortcutStateKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(trayTaskStateValue)
	return err == nil && v == 1
}
