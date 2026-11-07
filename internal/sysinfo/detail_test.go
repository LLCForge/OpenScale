package sysinfo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func smbiosStruct(formatted []byte, strs ...string) []byte {
	out := append([]byte(nil), formatted...)
	if len(strs) == 0 {
		return append(out, 0, 0)
	}
	for _, s := range strs {
		out = append(append(out, s...), 0)
	}
	return append(out, 0)
}

func formatted(typ byte, length int) []byte {
	f := make([]byte, length)
	f[0], f[1] = typ, byte(length)
	return f
}

func TestParseSMBIOSSkipsSerials(t *testing.T) {
	bios := formatted(0, 0x12)
	bios[0x04], bios[0x05], bios[0x08] = 1, 2, 3
	sys := formatted(1, 0x1B)
	sys[0x04], sys[0x05], sys[0x07] = 1, 2, 3
	board := formatted(2, 0x0F)
	board[0x04], board[0x05], board[0x07] = 1, 2, 3
	cpu := formatted(4, 0x30)
	binary.LittleEndian.PutUint16(cpu[0x14:], 4700)
	binary.LittleEndian.PutUint16(cpu[0x16:], 2900)
	cpu[0x18], cpu[0x23], cpu[0x25] = 0x41, 8, 16
	arr := formatted(16, 0x0F)
	arr[0x05] = 3
	binary.LittleEndian.PutUint16(arr[0x0D:], 4)
	mem := formatted(17, 0x28)
	binary.LittleEndian.PutUint16(mem[0x0C:], 16384)
	mem[0x0E], mem[0x12] = 0x09, 0x22
	binary.LittleEndian.PutUint16(mem[0x15:], 5600)
	binary.LittleEndian.PutUint16(mem[0x20:], 4800)
	mem[0x17], mem[0x18] = 1, 2
	empty := formatted(17, 0x28)
	var table []byte
	table = append(table, smbiosStruct(bios, "American Megatrends", "1.20", "05/13/2024")...)
	table = append(table, smbiosStruct(sys, "ASUS", "ROG Strix", "SYS-SERIAL-1")...)
	table = append(table, smbiosStruct(board, "ASUSTeK", "B650", "BOARD-SERIAL-2")...)
	table = append(table, smbiosStruct(cpu)...)
	table = append(table, smbiosStruct(arr)...)
	table = append(table, smbiosStruct(mem, "Kingston", "MEM-SERIAL-3")...)
	table = append(table, smbiosStruct(empty)...)
	table = append(table, smbiosStruct(formatted(127, 4))...)
	s := parseSMBIOS(table)
	if s.biosVendor != "American Megatrends" || s.biosVersion != "1.20" || biosDate(s.biosDate) != "2024-05-13" {
		t.Fatalf("bios: %+v", s)
	}
	if s.sysVendor != "ASUS" || s.sysProduct != "ROG Strix" || s.boardProduct != "B650" {
		t.Fatalf("system: %+v", s)
	}
	if s.cpuMaxMHz != 4700 || s.cpuCurMHz != 2900 || s.cpuCores != 8 || s.cpuThreads != 16 || s.cpuSockets != 1 {
		t.Fatalf("cpu: %+v", s)
	}
	if s.memSlots != 4 || len(s.modules) != 1 || s.modules[0] != (MemModule{Size: 16 << 30, Type: "DDR5", MHz: 4800, Form: "DIMM"}) {
		t.Fatalf("memory: %+v", s)
	}
	if strings.Contains(strings.ToLower(jsonString(t, s.modules)+s.sysProduct+s.boardProduct), "serial") {
		t.Fatal("a serial number was read")
	}
	// Truncated and garbage input must not panic.
	for i := range table {
		parseSMBIOS(table[:i])
	}
	parseSMBIOS([]byte{17, 2, 0, 0})
	parseSMBIOS(bytes.Repeat([]byte{0xFF}, 300))
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testEDID() []byte {
	b := make([]byte, 128)
	copy(b, []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00})
	b[8], b[9] = 0x10, 0xAC // "DEL"
	copy(b[54:], []byte{0x02, 0x3A, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40})
	copy(b[72:], append([]byte{0, 0, 0, 0xFC, 0}, "DELL U2720Q\n "...))
	copy(b[90:], append([]byte{0, 0, 0, 0xFF, 0}, "SERIAL12345\n "...))
	return b
}

func TestParseEDID(t *testing.T) {
	d, ok := parseEDID(testEDID())
	if !ok || d != (Display{Name: "DELL U2720Q", W: 1920, H: 1080, Hz: 60}) {
		t.Fatalf("edid = %+v %v", d, ok)
	}
	noName := testEDID()
	copy(noName[72:90], make([]byte, 18))
	if d, _ := parseEDID(noName); d.Name != "DEL" {
		t.Fatalf("vendor fallback = %q", d.Name)
	}
	if _, ok := parseEDID(make([]byte, 128)); ok {
		t.Fatal("bad header accepted")
	}
	if _, ok := parseEDID(testEDID()[:100]); ok {
		t.Fatal("short EDID accepted")
	}
}

func TestLinuxParsers(t *testing.T) {
	cpu := parseCPUInfo("processor\t: 0\nmodel name\t: AMD Ryzen 7 7700X\nphysical id\t: 0\ncore id\t\t: 0\ncpu MHz\t\t: 4500.123\nflags\t\t: fpu svm hypervisor\n\n" +
		"processor\t: 1\nmodel name\t: AMD Ryzen 7 7700X\nphysical id\t: 0\ncore id\t\t: 0\n\nprocessor\t: 2\nphysical id\t: 0\ncore id\t\t: 1\n")
	if cpu.model != "AMD Ryzen 7 7700X" || cpu.threads != 3 || cpu.cores != 2 || cpu.sockets != 1 || cpu.mhz != 4500 || !cpu.flags["svm"] || !cpu.flags["hypervisor"] {
		t.Fatalf("cpuinfo: %+v", cpu)
	}
	if p, n, v := parseOSRelease("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"); p != "Ubuntu 24.04.1 LTS" || n != "Ubuntu" || v != "24.04" {
		t.Fatalf("os-release: %q %q %q", p, n, v)
	}
	mi := parseMountInfo("22 1 0:21 / /proc rw - proc proc rw\n" +
		"25 1 259:2 / / rw - ext4 /dev/nvme0n1p2 rw\n" +
		"26 25 259:2 /home /home rw - ext4 /dev/nvme0n1p2 rw\n" +
		"27 25 259:1 / /boot/efi rw - vfat /dev/nvme0n1p1 rw\n" +
		"28 25 8:17 / /media/ayse/My\\040Disk rw - exfat /dev/sdb1 rw\n" +
		"29 25 0:45 / /mnt/data rw - btrfs /dev/mapper/luks-1 rw\n" +
		"30 25 7:3 / /snap/core/1 ro - squashfs /dev/loop3 ro\n")
	if len(mi) != 4 || mi[0].mount != "/" || mi[2].mount != "/media/ayse/My Disk" || mi[3].source != "/dev/mapper/luks-1" {
		t.Fatalf("mountinfo: %+v", mi)
	}
	routes := parseDefaultRoutes("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"+
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"+
		"wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n",
		strings.Repeat("0", 32)+" 00 "+strings.Repeat("0", 32)+" 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth1\n")
	if !routes["wlan0"] || !routes["eth1"] || len(routes) != 2 {
		t.Fatalf("routes: %v", routes)
	}
	if w := parseWireless("Inter-| sta-|   Quality        |\n face | status | link level noise |\nwlan0: 0000   56.  -54.  -256        0      0      0      0     12        0\n"); w["wlan0"] != 80 {
		t.Fatalf("wireless: %v", w)
	}
	ids := "# comment\n10de  NVIDIA Corporation\n\t2504  GA106 [GeForce RTX 3060 Lite Hash Rate]\n\t\t1462 3976  sub\n8086  Intel Corporation\n\t2723  Wi-Fi 6 AX200\nC 00  Unclassified device\n"
	if n := pciName(strings.NewReader(ids), "10de", "2504"); n != "NVIDIA GeForce RTX 3060 Lite Hash Rate" {
		t.Fatalf("pci: %q", n)
	}
	if n := pciName(strings.NewReader(ids), "8086", "2723"); n != "Intel Wi-Fi 6 AX200" {
		t.Fatalf("pci: %q", n)
	}
	if n := pciName(strings.NewReader(ids), "8086", "ffff"); n != "" {
		t.Fatalf("pci: %q", n)
	}
	utmp := make([]byte, 384*3)
	for i, u := range []string{"alice", "alice", "bob"} {
		binary.LittleEndian.PutUint16(utmp[i*384:], 7)
		copy(utmp[i*384+44:], u)
	}
	binary.LittleEndian.PutUint16(utmp[2*384:], 8) // DEAD_PROCESS
	if n := parseUtmpUsers(utmp); n != 1 {
		t.Fatalf("utmp users = %d", n)
	}
	if uid := parseSessionFile("UID=1000\nUSER=alice\nCLASS=user\nSTATE=active\n"); uid != "1000" {
		t.Fatalf("session uid %q", uid)
	}
	if uid := parseSessionFile("UID=120\nCLASS=greeter\nSTATE=online\n"); uid != "" {
		t.Fatalf("greeter counted: %q", uid)
	}
	attrs := map[string]string{"capacity": "81", "status": "Not charging", "energy_full_design": "57000000", "energy_full": "51300000", "cycle_count": "212"}
	b := linuxBattery(func(n string) string { return attrs[n] })
	if b == nil || *b != (Battery{Percent: 81, State: "ac", DesignMWh: 57000, FullMWh: 51300, Health: 90, Cycles: 212}) {
		t.Fatalf("battery: %+v", b)
	}
}

func TestParseSystemProfiler(t *testing.T) {
	data := []byte(`{
 "SPHardwareDataType":[{"_name":"hardware_overview","machine_name":"MacBook Air","machine_model":"Mac14,2","boot_rom_version":"11881.41.5","serial_number":"C02SERIAL","platform_UUID":"UUID-1"}],
 "SPDisplaysDataType":[{"_name":"Apple M2","sppci_model":"Apple M2","spdisplays_ndrvs":[{"_name":"Color LCD","_spdisplays_pixels":"2560 x 1664","_spdisplays_resolution":"1470 x 956 @ 60.00Hz"}]}],
 "SPStorageDataType":[{"_name":"Macintosh HD","mount_point":"/","file_system":"APFS","size_in_bytes":494384795648,"free_space_in_bytes":200000000000,"volume_uuid":"V-UUID","physical_drive":{"device_name":"APPLE SSD AP0512Z","medium_type":"ssd","protocol":"Apple Fabric","is_internal_disk":"yes"}},
   {"_name":"Yedek","mount_point":"/Volumes/Ornek Yedek","file_system":"ExFAT","size_in_bytes":1000,"free_space_in_bytes":10,"physical_drive":{"device_name":"Samsung T7","protocol":"USB","is_internal_disk":"no","medium_type":"ssd"}}],
 "SPPowerDataType":[{"_name":"spbattery_information","sppower_battery_charge_info":{"sppower_battery_state_of_charge":77,"sppower_battery_is_charging":"TRUE"},"sppower_battery_health_info":{"sppower_battery_cycle_count":103,"sppower_battery_health_maximum_capacity":"94%"},"sppower_battery_model_info":{"sppower_battery_serial_number":"BATSERIAL"}}],
 "SPMemoryDataType":[{"_name":"Memory","SPMemoryDataType":"16 GB","dimm_type":"LPDDR5"}],
 "SPNetworkDataType":[{"_name":"Wi-Fi","interface":"en0","type":"AirPort"},{"_name":"Thunderbolt Bridge","interface":"bridge0","type":"Bridge"}]
}`)
	p := parseSystemProfiler(data)
	if p.model != "MacBook Air" || p.modelID != "Mac14,2" || p.firmware != "11881.41.5" {
		t.Fatalf("hardware: %+v", p)
	}
	if len(p.gpus) != 1 || p.gpus[0].Model != "Apple M2" || len(p.displays) != 1 || p.displays[0] != (Display{Name: "Color LCD", W: 2560, H: 1664, Hz: 60}) {
		t.Fatalf("displays: %+v %+v", p.gpus, p.displays)
	}
	if len(p.disks) != 2 || p.disks[0].Type != "nvme" || p.disks[1].Bus != "usb" || !p.disks[1].Removable {
		t.Fatalf("disks: %+v", p.disks)
	}
	if len(p.volumes) != 2 || p.volumes[1].Mount != "/Volumes/*" || p.volumes[1].Disk != 1 {
		t.Fatalf("volumes: %+v", p.volumes)
	}
	if p.battery == nil || *p.battery != (Battery{Percent: 77, State: "charging", Health: 94, Cycles: 103}) {
		t.Fatalf("battery: %+v", p.battery)
	}
	if len(p.modules) != 1 || p.modules[0].Size != 16<<30 || p.nicTypes["en0"] != "wifi" || p.nicTypes["bridge0"] != "virtual" {
		t.Fatalf("memory/nics: %+v %v", p.modules, p.nicTypes)
	}
	all := jsonString(t, []any{p.gpus, p.displays, p.disks, p.volumes, p.battery, p.modules, p.model, p.modelID, p.firmware})
	for _, secret := range []string{"SERIAL", "UUID", "Ornek"} {
		if strings.Contains(all, secret) {
			t.Fatalf("%s leaked: %s", secret, all)
		}
	}
	parseSystemProfiler([]byte(`{"SPDisplaysDataType":[{"spdisplays_ndrvs":[1,"x",{"_spdisplays_pixels":"x"}]}],"SPPowerDataType":[{"_name":"spbattery_information"}]}`))
	parseSystemProfiler([]byte(`garbage`))
}

func TestPrivacyHelpers(t *testing.T) {
	if oui, random := OUI(net.HardwareAddr{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}); oui != "00:1a:2b" || random {
		t.Fatalf("oui %q %v", oui, random)
	}
	if _, random := OUI(net.HardwareAddr{0x3A, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}); !random {
		t.Fatal("locally administered address not flagged")
	}
	if oui, _ := OUI(net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}); oui != "" {
		t.Fatal("multicast address accepted")
	}
	for in, want := range map[string]string{
		"2001:db8:1:2:21a:2bff:fe3c:4d5e":  "2001:db8:1:2::/64",
		"2001:db8:1:2:abcd:1234:5678:9abc": "2001:db8:1:2:abcd:1234:5678:9abc",
		"fe80::21a:2bff:fe3c:4d5e":         "",
		"::1":                              "",
	} {
		if got := PrivateIPv6(netip.MustParseAddr(in)); got != want {
			t.Errorf("PrivateIPv6(%s) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"/": "/", "/home/ayse": "/home/*", "/media/ayse/USB": "/media/*", "/run/media/a/b": "/run/media/*", "/Volumes/Yedek": "/Volumes/*", "/mnt/data": "/mnt/data", "C:": "C:"} {
		if got := MaskMount(in); got != want {
			t.Errorf("MaskMount(%q) = %q", in, got)
		}
	}
	// A peer's report is cleaned again: a full MAC in the OUI field, an
	// EUI-64 address, a user folder and out-of-range values are dropped.
	d := Detail{Ver: 1, Users: 3,
		NICs:    []NIC{{Name: "eth0", OUI: "00:1a:2b:3c:4d:5e", Type: "bogus", IPv4: []string{"192.168.1.5", "x"}, IPv6: []string{"2001:db8::21a:2bff:fe3c:4d5e"}, Signal: 500}},
		Volumes: []Volume{{Mount: "/home/ayse/data", Disk: -7}},
		CPU:     CPUDetail{Virt: "maybe", Cores: -1},
		Board:   BoardDetail{BIOSDate: "13/05/2024", TPM: "3.0"},
	}
	d.sanitize()
	n := d.NICs[0]
	if n.OUI != "" || n.Type != "" || len(n.IPv4) != 1 || len(n.IPv6) != 1 || n.IPv6[0] != "2001:db8::/64" || n.Signal != 0 {
		t.Fatalf("nic not cleaned: %+v", n)
	}
	if d.Volumes[0].Mount != "/home/*" || d.Volumes[0].Disk != -1 || d.CPU.Virt != "" || d.CPU.Cores != 0 || d.Board.BIOSDate != "" || d.Board.TPM != "" {
		t.Fatalf("not cleaned: %+v", d)
	}
}

func TestDetailBlobRoundTripAndChunks(t *testing.T) {
	d := Detail{Ver: DetailVersion, At: 1700000000, Users: 1, OS: OSDetail{Name: "Windows 11 Pro", Version: "26H2", Build: "26300.9818"},
		Disks: []Disk{{Index: 0, Model: "Samsung SSD 990 PRO 2TB", Type: "nvme", Bus: "nvme", Size: 2 << 40}}}
	detailState.mu.Lock()
	out, id := publishDetailLocked(&d)
	detailState.mu.Unlock()
	if out == nil || !ValidDetailID(id) {
		t.Fatalf("publish: %v %q", out, id)
	}
	var blob []byte
	for off := 0; ; {
		chunk, total, cur, ok := DetailChunk(id, off, 100)
		if !ok || cur != id {
			t.Fatalf("chunk at %d: %v %q", off, ok, cur)
		}
		blob = append(blob, chunk...)
		off += len(chunk)
		if off >= total {
			break
		}
	}
	got, err := DecodeDetail(blob, id)
	if err != nil || got.OS.Build != "26300.9818" || len(got.Disks) != 1 || got.Disks[0].Size != 2<<40 {
		t.Fatalf("decode: %+v %v", got, err)
	}
	if _, err := DecodeDetail(blob, strings.Repeat("0", detailIDLen)); err == nil {
		t.Fatal("wrong identifier accepted")
	}
	if _, err := DecodeDetail(blob[:len(blob)/2], id); err == nil {
		t.Fatal("truncated blob accepted")
	}
	if _, _, cur, ok := DetailChunk(strings.Repeat("f", detailIDLen), 50, 100); !ok || cur == "" {
		t.Fatal("unknown identifier must serve the newest from offset 0")
	}
	if _, _, _, ok := DetailChunk(id, -1, 100); ok {
		t.Fatal("negative offset accepted")
	}
	// A gzip bomb is refused by the decompressed size limit.
	big := bytes.Repeat([]byte(" "), MaxDetailJSON+10)
	gz, _ := gzipBytes(big)
	if _, err := DecodeDetail(gz, detailID(big)); err == nil {
		t.Fatal("oversized inventory accepted")
	}
	c := NewDetailCache(1)
	c.Put("a", id, got, time.Unix(1, 0))
	if x, same := c.Get("a", id); x != got || !same {
		t.Fatal("cache miss")
	}
	c.Put("b", id, got, time.Unix(2, 0))
	if _, same := c.Get("a", id); same {
		t.Fatal("cache not bounded")
	}
}

func TestInfoCarriesOnlyTheAnnouncement(t *testing.T) {
	id := strings.Repeat("a", detailIDLen)
	in := Info{OS: "windows", DetailVer: DetailVersion, DetailID: id, Detail: &Detail{Ver: 1, OS: OSDetail{Name: "secret-detail"}}}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-detail") || !strings.Contains(string(data), `"xd":"`+id+`"`) {
		t.Fatalf("encoded: %s", data)
	}
	out, err := Decode([]byte(`{"os":"linux","xv":1,"xd":"` + id + `","x":{"v":1,"os":{"name":"injected"}}}`))
	if err != nil || out.Detail != nil || out.DetailID != id {
		t.Fatalf("decode: %+v %v", out, err)
	}
	if out, _ := Decode([]byte(`{"xv":1,"xd":"NOT-HEX"}`)); out.DetailID != "" || out.DetailVer != 0 {
		t.Fatalf("bad identifier kept: %+v", out)
	}
	// An old admin's decoder (no detail fields) still reads a new report.
	var old struct {
		OS string `json:"os"`
	}
	if err := json.Unmarshal(data, &old); err != nil || old.OS != "windows" {
		t.Fatalf("old decoder: %v", err)
	}
}

// TestCollectDetailThisMachine runs the real collectors once and checks
// that no full MAC address of this computer appears in the inventory.
func TestCollectDetailThisMachine(t *testing.T) {
	start := time.Now()
	d := CollectDetail(time.Now())
	data, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := gzipBytes(data)
	t.Logf("collected in %v, %d bytes JSON, %d bytes gzip", time.Since(start).Round(time.Millisecond), len(data), len(gz))
	if os.Getenv("OPENSCALE_PRINT_DETAIL") != "" {
		t.Logf("%s", data)
	}
	if len(data) > MaxDetailJSON || len(gz) > MaxDetailBlob {
		t.Fatalf("inventory over the limits: %d/%d", len(data), len(gz))
	}
	lower := strings.ToLower(string(data))
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if len(i.HardwareAddr) == 6 {
				full := strings.ToLower(i.HardwareAddr.String())
				if strings.Contains(lower, full) || strings.Contains(lower, strings.ReplaceAll(full, ":", "-")) {
					t.Fatalf("full MAC address of %s in the inventory", i.Name)
				}
			}
		}
	}
	if d.CPU.Threads < 1 || d.OS.Arch == "" {
		t.Fatalf("basic fields missing: %+v", d)
	}
}
