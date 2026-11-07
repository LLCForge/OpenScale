//go:build windows

package sysinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/openscale/openscale/internal/posture"
)

// Windows collection uses only system APIs and the registry: no WMI and no
// PowerShell (the one BitLocker query belongs to internal/posture and is
// shared through posture.VolumeEncryption). Everything is read-only.

var (
	procGetSystemFirmwareTable           = modKernel32.NewProc("GetSystemFirmwareTable")
	procGetLogicalProcessorInformationEx = modKernel32.NewProc("GetLogicalProcessorInformationEx")
	procGetSystemPowerStatus             = modKernel32.NewProc("GetSystemPowerStatus")
	procGetDynamicTimeZoneInformation    = modKernel32.NewProc("GetDynamicTimeZoneInformation")
	procGetFirmwareType                  = modKernel32.NewProc("GetFirmwareType")
	procGetPhysicallyInstalledMemory     = modKernel32.NewProc("GetPhysicallyInstalledSystemMemory")

	modPowrprof                = windows.NewLazySystemDLL("powrprof.dll")
	procCallNtPowerInformation = modPowrprof.NewProc("CallNtPowerInformation")

	modWtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = modWtsapi32.NewProc("WTSQuerySessionInformationW")

	modWlanapi             = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = modWlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

var (
	guidDevClassDisplay = windows.GUID{Data1: 0x4d36e968, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
	guidDevClassMonitor = windows.GUID{Data1: 0x4d36e96e, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
	guidDeviceBattery   = windows.GUID{Data1: 0x72631e54, Data2: 0x78a4, Data3: 0x11d0, Data4: [8]byte{0xbc, 0xf7, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a}}
)

const (
	ioctlStorageQueryProperty   = 0x002D1400
	ioctlDiskGetDriveGeometryEx = 0x000700A0
	ioctlVolumeGetDiskExtents   = 0x00560000
	ioctlBatteryQueryTag        = 0x00294040
	ioctlBatteryQueryInfo       = 0x00294044

	pfVirtFirmwareEnabled = 21
	wlanCurrentConnection = 7
	wtsUserName           = 5
	wtsDomainName         = 7
	processorInformation  = 11
)

func collectDetail(d *Detail) {
	safely(func() { winOS(d) })
	var sm smbiosInfo
	safely(func() { sm = winSMBIOS() })
	safely(func() { winBoard(d, sm) })
	safely(func() { winCPU(d, sm) })
	safely(func() { winMemory(d, sm) })
	safely(func() { d.GPUs = winGPUs() })
	safely(func() { d.Displays = winDisplays() })
	safely(func() { d.Board.TPM, d.Board.TPMVendor = tpmDetail() })
	safely(func() { d.Disks = winDisks() })
	safely(func() { d.Volumes = winVolumes() })
	safely(func() { d.NICs = winNICs() })
	safely(func() { d.Battery = winBatteryHealth() })
}

func collectLight(d *Detail) {
	safely(func() { winPower(d) })
	safely(func() { d.Users = winUsers() })
}

// ---- operating system ----

func winOS(d *Detail) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		product, _, _ := k.GetStringValue("ProductName")
		d.OS.Version, _, _ = k.GetStringValue("DisplayVersion")
		build, _, _ := k.GetStringValue("CurrentBuildNumber")
		d.OS.Edition, _, _ = k.GetStringValue("EditionID")
		d.OS.InstallType, _, _ = k.GetStringValue("InstallationType")
		if ubr, _, err := k.GetIntegerValue("UBR"); err == nil && build != "" {
			build += "." + strconv.FormatUint(ubr, 10)
		}
		if t, _, err := k.GetIntegerValue("InstallDate"); err == nil {
			d.OS.Installed = int64(t)
		}
		k.Close()
		v := windows.RtlGetVersion()
		if v.BuildNumber >= 22000 {
			product = strings.Replace(product, "Windows 10", "Windows 11", 1)
		}
		d.OS.Name, d.OS.Build = product, build
		d.OS.Kernel = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	}
	for _, p := range []string{`SOFTWARE\Microsoft\WindowsSelfHost\Applicability`, `SOFTWARE\Microsoft\WindowsSelfHost\UI\Selection`} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE); err == nil {
			for _, name := range []string{"BranchName", "UIBranch"} {
				if s, _, err := k.GetStringValue(name); err == nil && s != "" && d.OS.Channel == "" {
					d.OS.Channel = s
				}
			}
			k.Close()
		}
	}
	if ms, _, _ := procGetTickCount64.Call(); ms != 0 {
		d.OS.Boot = roundMinute(time.Now().Add(-time.Duration(ms) * time.Millisecond))
	}
	var tz dynamicTimeZoneInformation
	if r, _, _ := procGetDynamicTimeZoneInformation.Call(uintptr(unsafe.Pointer(&tz))); r != 0xFFFFFFFF {
		d.OS.TZ = windows.UTF16ToString(tz.TimeZoneKeyName[:])
	}
	var proc, native uint16
	if windows.IsWow64Process2(windows.CurrentProcess(), &proc, &native) == nil {
		switch native {
		case 0x8664:
			d.OS.Arch = "amd64"
		case 0xAA64:
			d.OS.Arch = "arm64"
		case 0x014C:
			d.OS.Arch = "386"
		}
	}
}

type dynamicTimeZoneInformation struct {
	Bias                        int32
	StandardName                [32]uint16
	StandardDate                windows.Systemtime
	StandardBias                int32
	DaylightName                [32]uint16
	DaylightDate                windows.Systemtime
	DaylightBias                int32
	TimeZoneKeyName             [128]uint16
	DynamicDaylightTimeDisabled byte
}

func roundMinute(t time.Time) int64 { return t.Round(time.Minute).Unix() }

// ---- firmware tables, board and processor ----

func winSMBIOS() smbiosInfo {
	const rsmb = 0x52534D42 // 'RSMB'
	n, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if n < 8 || n > maxSMBIOS {
		return smbiosInfo{}
	}
	buf := make([]byte, n)
	if r, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), n); r != n {
		return smbiosInfo{}
	}
	size := int(binary.LittleEndian.Uint32(buf[4:8]))
	if size > len(buf)-8 {
		size = len(buf) - 8
	}
	return parseSMBIOS(buf[8 : 8+size])
}

func winBoard(d *Detail, sm smbiosInfo) {
	b := &d.Board
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); err == nil {
		get := func(name string) string { s, _, _ := k.GetStringValue(name); return cleanFirmwareText(s) }
		b.Vendor, b.Model = get("SystemManufacturer"), get("SystemProductName")
		b.BoardVendor, b.BoardModel = get("BaseBoardManufacturer"), get("BaseBoardProduct")
		b.BIOSVendor, b.BIOSVersion = get("BIOSVendor"), get("BIOSVersion")
		b.BIOSDate = biosDate(get("BIOSReleaseDate"))
		k.Close()
	}
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = cleanFirmwareText(v)
		}
	}
	fill(&b.Vendor, sm.sysVendor)
	fill(&b.Model, sm.sysProduct)
	fill(&b.BoardVendor, sm.boardVendor)
	fill(&b.BoardModel, sm.boardProduct)
	fill(&b.BIOSVendor, sm.biosVendor)
	fill(&b.BIOSVersion, sm.biosVersion)
	if b.BIOSDate == "" {
		b.BIOSDate = biosDate(sm.biosDate)
	}
	var fw uint32
	if r, _, _ := procGetFirmwareType.Call(uintptr(unsafe.Pointer(&fw))); r != 0 {
		switch fw {
		case 1:
			b.Firmware, b.SecureBoot = "bios", "unsupported"
		case 2:
			b.Firmware = "uefi"
		}
	}
	if b.Firmware == "uefi" {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE); err == nil {
			if v, _, err := k.GetIntegerValue("UEFISecureBootEnabled"); err == nil {
				b.SecureBoot = map[bool]string{true: "on", false: "off"}[v != 0]
			}
			k.Close()
		}
	}
}

func winCPU(d *Detail, sm smbiosInfo) {
	c := &d.CPU
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		c.Model, _, _ = k.GetStringValue("ProcessorNameString")
		c.Model = strings.TrimSpace(c.Model)
		if mhz, _, err := k.GetIntegerValue("~MHz"); err == nil {
			c.BaseMHz = int(mhz)
		}
		k.Close()
	}
	if cores, threads := logicalProcessors(0); cores > 0 {
		c.Cores, c.Threads = cores, threads
	}
	if pkgs, _ := logicalProcessors(3); pkgs > 0 {
		c.Sockets = pkgs
	}
	// PROCESSOR_POWER_INFORMATION: MaxMhz is the rated (base) frequency.
	n := max(c.Threads, 1)
	buf := make([]byte, 24*n)
	if r, _, _ := procCallNtPowerInformation.Call(processorInformation, 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); r == 0 {
		base := 0
		for i := range n {
			base = max(base, int(binary.LittleEndian.Uint32(buf[24*i+4:])))
		}
		if base > 0 {
			c.BaseMHz = base
		}
	}
	if sm.cpuMaxMHz > c.BaseMHz {
		c.MaxMHz = sm.cpuMaxMHz
	}
	switch {
	case windows.IsProcessorFeaturePresent(pfVirtFirmwareEnabled):
		c.Virt = "on"
	case hypervisorRunning() || virtFromModel(sm.sysVendor, sm.sysProduct) != "":
		c.Virt = "hv"
	default:
		c.Virt = "off"
	}
}

// logicalProcessors counts GetLogicalProcessorInformationEx entries of the
// relationship (0 cores, 3 packages) and the logical processors in them.
func logicalProcessors(relation uintptr) (entries, threads int) {
	var size uint32
	procGetLogicalProcessorInformationEx.Call(relation, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > 1<<22 {
		return 0, 0
	}
	buf := make([]byte, size)
	if r, _, _ := procGetLogicalProcessorInformationEx.Call(relation, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return 0, 0
	}
	affinity := int(unsafe.Sizeof(uintptr(0)))
	maskSize := affinity + 8
	for off := 0; off+8 <= int(size); {
		entrySize := int(binary.LittleEndian.Uint32(buf[off+4:]))
		if entrySize < 32 || off+entrySize > int(size) {
			break
		}
		e := buf[off : off+entrySize]
		entries++
		groups := int(binary.LittleEndian.Uint16(e[30:]))
		for g := 0; g < groups && 32+(g+1)*maskSize <= len(e); g++ {
			m := e[32+g*maskSize:]
			if affinity == 8 {
				threads += bits.OnesCount64(binary.LittleEndian.Uint64(m))
			} else {
				threads += bits.OnesCount32(binary.LittleEndian.Uint32(m))
			}
		}
		off += entrySize
	}
	return entries, threads
}

// hypervisorRunning reports whether the Hyper-V host service runs (the
// root partition of Hyper-V, WSL 2 or virtualization-based security).
func hypervisorRunning() bool {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("hvservice")
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	return windows.QueryServiceStatus(s, &st) == nil && st.CurrentState == windows.SERVICE_RUNNING
}

func winMemory(d *Detail, sm smbiosInfo) {
	var kb uint64
	if r, _, _ := procGetPhysicallyInstalledMemory.Call(uintptr(unsafe.Pointer(&kb))); r != 0 {
		d.Mem.Total = kb << 10
	}
	if d.Mem.Total == 0 {
		ms := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
		if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
			d.Mem.Total = ms.TotalPhys
		}
	}
	d.Mem.Slots, d.Mem.Modules = sm.memSlots, sm.modules
}

// ---- display adapters and monitors (SetupAPI; works in session 0) ----

func eachPresentDevice(class *windows.GUID, fn func(set windows.DevInfo, data *windows.DevInfoData)) {
	set, err := windows.SetupDiGetClassDevsEx(class, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return
	}
	defer set.Close()
	for i := 0; i < 64; i++ {
		data, err := set.EnumDeviceInfo(i)
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				return
			}
			continue
		}
		fn(set, data)
	}
}

func openDevKey(set windows.DevInfo, data *windows.DevInfoData, kind windows.DIREG) (registry.Key, bool) {
	h, err := set.OpenDevRegKey(data, windows.DICS_FLAG_GLOBAL, 0, kind, windows.KEY_READ)
	if err != nil {
		return 0, false
	}
	return registry.Key(h), true
}

func winGPUs() []GPU {
	var out []GPU
	eachPresentDevice(&guidDevClassDisplay, func(set windows.DevInfo, data *windows.DevInfoData) {
		k, ok := openDevKey(set, data, windows.DIREG_DRV)
		if !ok {
			return
		}
		defer k.Close()
		match, _, _ := k.GetStringValue("MatchingDeviceId")
		desc, _, _ := k.GetStringValue("DriverDesc")
		if strings.HasPrefix(strings.ToLower(match), "rdpidd") || desc == "" {
			return // remote desktop's indirect display adapters
		}
		g := GPU{Model: desc}
		g.Driver, _, _ = k.GetStringValue("DriverVersion")
		if v, _, err := k.GetIntegerValue("HardwareInformation.qwMemorySize"); err == nil {
			g.VRAM = v
		} else if b, _, err := k.GetBinaryValue("HardwareInformation.MemorySize"); err == nil && len(b) >= 4 {
			g.VRAM = uint64(binary.LittleEndian.Uint32(b))
		} else if v, _, err := k.GetIntegerValue("HardwareInformation.MemorySize"); err == nil {
			g.VRAM = v
		}
		out = append(out, g)
	})
	return out
}

func winDisplays() []Display {
	var out []Display
	eachPresentDevice(&guidDevClassMonitor, func(set windows.DevInfo, data *windows.DevInfoData) {
		k, ok := openDevKey(set, data, windows.DIREG_DEV)
		if !ok {
			return
		}
		edid, _, err := k.GetBinaryValue("EDID")
		k.Close()
		if err != nil {
			return
		}
		if disp, ok := parseEDID(edid); ok {
			out = append(out, disp)
		}
	})
	return out
}

// ---- disks and volumes ----

func openDevice(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	// Access 0: only metadata IOCTLs, no reads, no administrator right.
	return windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

func ioctl(h windows.Handle, code uint32, in []byte, out []byte) (int, bool) {
	var n uint32
	var inPtr *byte
	if len(in) > 0 {
		inPtr = &in[0]
	}
	err := windows.DeviceIoControl(h, code, inPtr, uint32(len(in)), &out[0], uint32(len(out)), &n, nil)
	return int(n), err == nil
}

func winDisks() []Disk {
	var out []Disk
	for i := 0; i < 32; i++ {
		h, err := openDevice(fmt.Sprintf(`\\.\PhysicalDrive%d`, i))
		if err != nil {
			continue
		}
		disk := Disk{Index: i}
		desc := make([]byte, 1024)
		query := make([]byte, 12) // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
		if n, ok := ioctl(h, ioctlStorageQueryProperty, query, desc); ok && n >= 36 {
			desc = desc[:n]
			str := func(off int) string {
				o := int(binary.LittleEndian.Uint32(desc[off:]))
				if o <= 0 || o >= len(desc) {
					return ""
				}
				s := desc[o:]
				if j := strings.IndexByte(string(s), 0); j >= 0 {
					s = s[:j]
				}
				return strings.TrimSpace(string(s))
			}
			// Offset 24 is the serial number: never read.
			disk.Model = joinModel(str(12), str(16))
			disk.Removable = desc[10] != 0
			disk.Bus = storageBus(binary.LittleEndian.Uint32(desc[28:]))
		}
		seek := make([]byte, 12)
		binary.LittleEndian.PutUint32(query, 7) // StorageDeviceSeekPenaltyProperty
		if n, ok := ioctl(h, ioctlStorageQueryProperty, query, seek); ok && n >= 9 {
			if seek[8] != 0 {
				disk.Type = "hdd"
			} else {
				disk.Type = "ssd"
			}
		}
		switch {
		case disk.Bus == "nvme":
			disk.Type = "nvme"
		case disk.Bus == "virtual" || virtualDiskModel(disk.Model):
			disk.Bus, disk.Type = "virtual", "" // the seek penalty of a virtual disk means nothing
		}
		geo := make([]byte, 256)
		if n, ok := ioctl(h, ioctlDiskGetDriveGeometryEx, nil, geo); ok && n >= 32 {
			disk.Size = binary.LittleEndian.Uint64(geo[24:])
		}
		windows.CloseHandle(h)
		if disk.Bus == "usb" {
			disk.Removable = true
		}
		out = append(out, disk)
	}
	return out
}

func storageBus(t uint32) string {
	switch t {
	case 0x1:
		return "scsi"
	case 0x2, 0x3:
		return "ata"
	case 0x4:
		return "firewire"
	case 0x6:
		return "fibre"
	case 0x7:
		return "usb"
	case 0x8:
		return "raid"
	case 0x9:
		return "iscsi"
	case 0xA:
		return "sas"
	case 0xB:
		return "sata"
	case 0xC:
		return "sd"
	case 0xD:
		return "mmc"
	case 0xE, 0xF:
		return "virtual"
	case 0x10:
		return "spaces"
	case 0x11:
		return "nvme"
	case 0x13:
		return "ufs"
	}
	return "other"
}

func winVolumes() []Volume {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || n == 0 || int(n) > len(buf) {
		return nil
	}
	enc := posture.VolumeEncryption()
	var out []Volume
	for _, root := range strings.Split(windows.UTF16ToString(buf[:n]), "\x00") {
		if len(root) < 2 || root[1] != ':' {
			continue
		}
		rp, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		kind := windows.GetDriveType(rp)
		if kind != windows.DRIVE_FIXED && kind != windows.DRIVE_REMOVABLE && kind != windows.DRIVE_RAMDISK {
			continue
		}
		fsName := make([]uint16, 64)
		if windows.GetVolumeInformation(rp, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName))) != nil {
			continue // no media
		}
		letter := strings.ToUpper(root[:2])
		v := Volume{Mount: letter, FS: windows.UTF16ToString(fsName), Removable: kind == windows.DRIVE_REMOVABLE, Disk: -1}
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(rp, &free, &total, &totalFree) == nil {
			v.Size, v.Free = total, totalFree
		}
		switch enc[letter] {
		case posture.On:
			v.Encrypted = "on"
		case posture.Off:
			v.Encrypted = "off"
		}
		if h, err := openDevice(`\\.\` + letter); err == nil {
			ext := make([]byte, 256)
			if n, ok := ioctl(h, ioctlVolumeGetDiskExtents, nil, ext); ok && n >= 16 && binary.LittleEndian.Uint32(ext) >= 1 {
				v.Disk = int(binary.LittleEndian.Uint32(ext[8:]))
			}
			windows.CloseHandle(h)
		}
		out = append(out, v)
	}
	return out
}

// ---- network adapters ----

func winNICs() []NIC {
	size := uint32(32 << 10)
	var buf []byte
	for range 4 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size > 4<<20 {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	wifi := wlanStatus()
	var out []NIC
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == windows.IF_TYPE_TUNNEL {
			continue
		}
		row := windows.MibIfRow2{InterfaceLuid: a.Luid}
		hardware := windows.GetIfEntry2Ex(2, &row) == nil && row.InterfaceAndOperStatusFlags&0x01 != 0
		up := a.OperStatus == windows.IfOperStatusUp
		if !hardware && !up {
			continue
		}
		n := NIC{
			Name:  windows.UTF16PtrToString(a.FriendlyName),
			Model: windows.UTF16PtrToString(a.Description),
			Up:    up,
		}
		switch {
		case a.IfType == windows.IF_TYPE_IEEE80211:
			n.Type = "wifi"
		case a.IfType == 243 || a.IfType == 244:
			n.Type = "cellular"
		case strings.Contains(strings.ToLower(n.Model), "bluetooth"):
			n.Type = "bluetooth"
		case !hardware:
			n.Type = "virtual"
		case a.IfType == windows.IF_TYPE_ETHERNET_CSMACD:
			n.Type = "ethernet"
		default:
			n.Type = "other"
		}
		if a.PhysicalAddressLength == 6 {
			n.OUI, n.RandomMAC = OUI(a.PhysicalAddress[:6])
		}
		if up && a.TransmitLinkSpeed > 0 && a.TransmitLinkSpeed != ^uint64(0) {
			n.Speed = a.TransmitLinkSpeed / 1_000_000
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			ip, ok := netip.AddrFromSlice(u.Address.IP())
			if !ok {
				continue
			}
			if ip.Is4() || ip.Is4In6() {
				n.IPv4 = append(n.IPv4, ip.Unmap().String())
			} else if s := PrivateIPv6(ip); s != "" {
				n.IPv6 = append(n.IPv6, s)
			}
		}
		n.Gateway = a.FirstGatewayAddress != nil
		if w, ok := wifi[strings.ToUpper(windows.BytePtrToString(a.AdapterName))]; ok && n.Type == "wifi" {
			n.Signal, n.WiFiStd = w.signal, w.std
		}
		out = append(out, n)
		if len(out) >= maxNICs {
			break
		}
	}
	return out
}

type wlanInfo struct {
	signal int
	std    string
}

// wlanStatus returns the signal quality and PHY standard of connected
// Wi-Fi interfaces by adapter GUID. The connection attributes also hold
// the profile and network name: those bytes are never read.
func wlanStatus() map[string]wlanInfo {
	out := map[string]wlanInfo{}
	if procWlanOpenHandle.Find() != nil {
		return out
	}
	var negotiated uint32
	var h windows.Handle
	if r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h))); r != 0 {
		return out
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)
	var list *byte
	if r, _, _ := procWlanEnumInterfaces.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&list))); r != 0 || list == nil {
		return out
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(list)))
	head := unsafe.Slice(list, 8)
	count := min(int(binary.LittleEndian.Uint32(head)), 16)
	const itemSize = 16 + 512 + 4
	items := unsafe.Slice(list, 8+count*itemSize)
	for i := range count {
		item := items[8+i*itemSize : 8+(i+1)*itemSize]
		if binary.LittleEndian.Uint32(item[528:]) != 1 { // wlan_interface_state_connected
			continue
		}
		guid := (*windows.GUID)(unsafe.Pointer(&item[0]))
		var size uint32
		var data *byte
		if r, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), wlanCurrentConnection, 0,
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0); r != 0 || data == nil {
			continue
		}
		if size >= 588 {
			attr := unsafe.Slice(data, 588)
			// WLAN_ASSOCIATION_ATTRIBUTES starts at 520; skip SSID (520-555)
			// and BSSID (560-565).
			phy := binary.LittleEndian.Uint32(attr[568:])
			signal := int(binary.LittleEndian.Uint32(attr[576:]))
			out[strings.ToUpper(guid.String())] = wlanInfo{signal: signal, std: dot11Standard(phy)}
		}
		procWlanFreeMemory.Call(uintptr(unsafe.Pointer(data)))
	}
	return out
}

func dot11Standard(phy uint32) string {
	switch phy {
	case 2, 5:
		return "802.11b"
	case 4:
		return "802.11a"
	case 6:
		return "802.11g"
	case 7:
		return "802.11n"
	case 8:
		return "802.11ac"
	case 9:
		return "802.11ad"
	case 10:
		return "802.11ax"
	case 11:
		return "802.11be"
	}
	return ""
}

// ---- battery and sessions ----

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

func winPower(d *Detail) {
	var ps systemPowerStatus
	if r, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&ps))); r == 0 {
		return
	}
	if ps.BatteryFlag == 128 || ps.BatteryFlag == 255 || ps.BatteryLifePercent > 100 {
		return // no system battery, or unknown
	}
	b := &Battery{Percent: int(ps.BatteryLifePercent)}
	switch {
	case ps.BatteryFlag&8 != 0:
		b.State = "charging"
	case ps.ACLineStatus == 1 && ps.BatteryLifePercent >= 100:
		b.State = "full"
	case ps.ACLineStatus == 1:
		b.State = "ac"
	case ps.ACLineStatus == 0:
		b.State = "discharging"
	}
	d.Battery = b
}

// winBatteryHealth reads design and full-charge capacity through the
// battery class driver (IOCTL_BATTERY_QUERY_INFORMATION).
func winBatteryHealth() *Battery {
	paths, err := windows.CM_Get_Device_Interface_List("", &guidDeviceBattery, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
	if err != nil || len(paths) == 0 {
		return nil
	}
	var design, full uint64
	var cycles int
	relative := false
	for _, p := range paths[:min(len(paths), 4)] {
		pp, err := windows.UTF16PtrFromString(p)
		if err != nil {
			continue
		}
		h, err := windows.CreateFile(pp, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			continue
		}
		wait := make([]byte, 4)
		tag := make([]byte, 4)
		if _, ok := ioctl(h, ioctlBatteryQueryTag, wait, tag); ok && binary.LittleEndian.Uint32(tag) != 0 {
			q := make([]byte, 12) // BatteryTag, InformationLevel 0 (BatteryInformation), AtRate
			copy(q, tag)
			info := make([]byte, 32)
			if n, ok := ioctl(h, ioctlBatteryQueryInfo, q, info); ok && n >= 32 {
				caps := binary.LittleEndian.Uint32(info)
				if caps&0x80000000 != 0 { // BATTERY_SYSTEM_BATTERY
					relative = relative || caps&0x40000000 != 0
					design += uint64(binary.LittleEndian.Uint32(info[12:]))
					full += uint64(binary.LittleEndian.Uint32(info[16:]))
					cycles = max(cycles, int(binary.LittleEndian.Uint32(info[28:])))
				}
			}
		}
		windows.CloseHandle(h)
	}
	if design == 0 {
		return nil
	}
	b := &Battery{Cycles: cycles, Health: int((full*100 + design/2) / design)}
	if !relative {
		b.DesignMWh, b.FullMWh = design, full
	}
	return b
}

// winUsers counts the distinct users with a logon session. The names are
// compared here and dropped.
func winUsers() int {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count) != nil {
		return -1
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	query := func(id uint32, class uintptr) string {
		var p *uint16
		var n uint32
		if r, _, _ := procWTSQuerySessionInformation.Call(0, uintptr(id), class, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n))); r == 0 || p == nil {
			return ""
		}
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(p)))
		return windows.UTF16PtrToString(p)
	}
	users := map[string]bool{}
	for _, s := range unsafe.Slice(sessions, min(count, 1024)) {
		if name := query(s.SessionID, wtsUserName); name != "" {
			users[strings.ToLower(query(s.SessionID, wtsDomainName)+`\`+name)] = true
		}
	}
	return len(users)
}
