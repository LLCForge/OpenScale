//go:build windows

package winapp

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceInfo is the state "openscale service status" shows (F-148).
type ServiceInfo struct {
	Installed bool
	Running   bool
	Automatic bool
	State     string
	Binary    string
	PID       uint32
}

var serviceStateNames = map[svc.State]string{
	svc.Stopped:         "durdu",
	svc.StartPending:    "başlıyor",
	svc.StopPending:     "duruyor",
	svc.Running:         "çalışıyor",
	svc.ContinuePending: "devam ediyor",
	svc.PausePending:    "duraklıyor",
	svc.Paused:          "duraklatıldı",
}

// QueryService reads the service's state and configuration. It needs only
// query rights, so it works without elevation.
func QueryService() (ServiceInfo, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return ServiceInfo{}, wrapWinErr("servis yöneticisine bağlanılamadı", err)
	}
	m := &mgr.Mgr{Handle: scm}
	defer m.Disconnect()
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return ServiceInfo{}, err
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return ServiceInfo{State: "kurulu değil"}, nil
		}
		return ServiceInfo{}, wrapWinErr("servis açılamadı", err)
	}
	s := &mgr.Service{Name: ServiceName, Handle: h}
	defer s.Close()
	info := ServiceInfo{Installed: true}
	st, err := s.Query()
	if err != nil {
		return info, wrapWinErr("servis durumu okunamadı", err)
	}
	info.Running, info.PID = st.State == svc.Running, st.ProcessId
	info.State = serviceStateNames[st.State]
	if cfg, err := s.Config(); err == nil {
		info.Binary, info.Automatic = cfg.BinaryPathName, cfg.StartType == mgr.StartAutomatic
	}
	return info, nil
}
