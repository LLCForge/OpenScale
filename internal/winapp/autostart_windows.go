//go:build windows

package winapp

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func runRoot(allUsers bool) registry.Key {
	if allUsers {
		return registry.LOCAL_MACHINE
	}
	return registry.CURRENT_USER
}

// SetRunEntry writes the Run value. allUsers needs an elevated process.
func SetRunEntry(allUsers bool, command string) error {
	if command == "" || RunCommandProgram(command) == "" {
		return ErrBadRunCommand
	}
	k, _, err := registry.CreateKey(runRoot(allUsers), RunKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return wrapWinErr("başlangıç kaydı açılamadı", err)
	}
	defer k.Close()
	if err := k.SetStringValue(RunValueName, command); err != nil {
		return wrapWinErr("başlangıç kaydı yazılamadı", err)
	}
	return nil
}

// DeleteRunEntry removes the Run value; a missing value is not an error.
func DeleteRunEntry(allUsers bool) error {
	k, err := registry.OpenKey(runRoot(allUsers), RunKeyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return wrapWinErr("başlangıç kaydı açılamadı", err)
	}
	defer k.Close()
	if err := k.DeleteValue(RunValueName); err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return wrapWinErr("başlangıç kaydı silinemedi", err)
	}
	return nil
}

// GetRunEntry returns the Run value and whether it exists.
func GetRunEntry(allUsers bool) (string, bool, error) {
	k, err := registry.OpenKey(runRoot(allUsers), RunKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return "", false, nil
	}
	if err != nil {
		return "", false, wrapWinErr("başlangıç kaydı okunamadı", err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue(RunValueName)
	if errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return "", false, nil
	}
	if err != nil {
		return "", false, wrapWinErr("başlangıç kaydı okunamadı", err)
	}
	return v, true, nil
}
