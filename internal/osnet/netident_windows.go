//go:build windows

package osnet

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Wi-Fi names come from the WLAN API (WlanQueryInterface with
// wlan_intf_opcode_current_connection); wired networks from the adapter
// list (an up Ethernet adapter with a default gateway).

var (
	modwlanapi             = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = modwlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modwlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modwlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modwlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = modwlanapi.NewProc("WlanFreeMemory")
)

const (
	wlanClientVersion            = 2
	wlanOpcodeCurrentConnection  = 7
	wlanInterfaceStateConnected  = 1
	wlanInterfaceInfoSize        = 16 + 512 + 4
	wlanConnAttrSSIDLengthOffset = 4 + 4 + 512
	wlanConnAttrMinSize          = wlanConnAttrSSIDLengthOffset + 4 + 32
	maxWlanInterfaces            = 64
)

// CurrentNetworks lists the connected Wi-Fi networks and wired adapters.
func CurrentNetworks() ([]CurrentNetwork, error) {
	nets, wifiErr := wifiNetworks()
	wired, err := wiredNetworks()
	if err != nil {
		return nil, err
	}
	nets = append(nets, wired...)
	if wifiErr != nil && len(nets) == 0 {
		return nil, wifiErr
	}
	return nets, nil
}

func wifiNetworks() ([]CurrentNetwork, error) {
	if err := modwlanapi.Load(); err != nil {
		return nil, nil // no WLAN API: no Wi-Fi on this computer
	}
	var negotiated uint32
	var h windows.Handle
	if r, _, _ := procWlanOpenHandle.Call(wlanClientVersion, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h))); r != 0 {
		// The WLAN service is not running: no Wi-Fi in use.
		return nil, nil
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)
	var list unsafe.Pointer
	if r, _, _ := procWlanEnumInterfaces.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&list))); r != 0 {
		return nil, windows.Errno(r)
	}
	if list == nil {
		return nil, nil
	}
	defer procWlanFreeMemory.Call(uintptr(list))
	n := *(*uint32)(list)
	if n > maxWlanInterfaces {
		return nil, errors.New("too many WLAN interfaces")
	}
	var nets []CurrentNetwork
	for i := uint32(0); i < n; i++ {
		info := unsafe.Add(list, 8+uintptr(i)*wlanInterfaceInfoSize)
		state := *(*uint32)(unsafe.Add(info, 16+512))
		if state != wlanInterfaceStateConnected {
			continue
		}
		var size uint32
		var data unsafe.Pointer
		r, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(info), wlanOpcodeCurrentConnection, 0,
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
		if r != 0 || data == nil {
			continue
		}
		name := ""
		if size >= wlanConnAttrMinSize {
			l := *(*uint32)(unsafe.Add(data, wlanConnAttrSSIDLengthOffset))
			if l <= 32 {
				ssid := unsafe.Slice((*byte)(unsafe.Add(data, wlanConnAttrSSIDLengthOffset+4)), l)
				name = cleanNetworkName(string(ssid))
			}
		}
		procWlanFreeMemory.Call(uintptr(data))
		nets = append(nets, CurrentNetwork{Kind: NetworkWiFi, Name: name})
	}
	return nets, nil
}

func wiredNetworks() ([]CurrentNetwork, error) {
	size := uint32(15000)
	for range 4 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var nets []CurrentNetwork
		for a := first; a != nil; a = a.Next {
			if a.IfType != windows.IF_TYPE_ETHERNET_CSMACD || a.OperStatus != windows.IfOperStatusUp || a.FirstGatewayAddress == nil {
				continue
			}
			nets = append(nets, CurrentNetwork{Kind: NetworkWired, Name: cleanNetworkName(windows.UTF16PtrToString(a.FriendlyName))})
		}
		return nets, nil
	}
	return nil, errors.New("adapter list keeps growing")
}
